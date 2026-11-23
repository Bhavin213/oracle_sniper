"""
OCI Always Free A1 "sniper".

Keeps trying to launch a VM.Standard.A1.Flex instance until Oracle has capacity,
then emails you the details. Designed to run from GitHub Actions on a cron, but
works the same on any Linux box.

SAFE FOR PUBLIC REPOS: GitHub Actions logs of a public repo are public, so this
script never prints OCIDs, IPs, emails or names of your resources. Everything
it logs goes through redact(), and the sensitive details are sent only by email.

All configuration comes from environment variables (see README.md).
"""

import os
import re
import smtplib
import sys
import time
from email.message import EmailMessage

import oci

IN_GITHUB = os.environ.get("GITHUB_ACTIONS") == "true"

# --------------------------------------------------------------------------- #
# Redaction - nothing identifying may reach the (public) log
# --------------------------------------------------------------------------- #

_REDACT_PATTERNS = [
    (re.compile(r"ocid1\.[A-Za-z0-9._-]+"), "ocid1.***"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "x.x.x.x"),
    (re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"), "***@***"),
    (re.compile(r"\b[A-Za-z0-9]{4}:[A-Z]{2}-[A-Z]+-\d-(AD-\d)\b"), r"****:\1"),
    (re.compile(r"(?:[0-9a-f]{2}:){15}[0-9a-f]{2}", re.I), "**:**"),
    (re.compile(r"-----BEGIN[\s\S]*?-----END[^-]*-----"), "[private key]"),
    (re.compile(r"https?://\S+"), "[url]"),  # SDK errors embed OCIDs in URLs
]


def redact(text):
    text = str(text)
    for pattern, repl in _REDACT_PATTERNS:
        text = pattern.sub(repl, text)
    return text


def mask(value):
    """Ask GitHub to mask a value we discovered at runtime (belt and braces)."""
    if IN_GITHUB and value:
        print(f"::add-mask::{value}", flush=True)


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {redact(msg)}", flush=True)


def fail(msg):
    log(f"ERROR: {msg}")
    sys.exit(1)


def describe_error(err):
    """Short, safe description of an OCI ServiceError (its str() leaks OCIDs)."""
    return redact(f"HTTP {err.status} {err.code}: {err.message}")


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #


def env(name, default=None, required=False):
    value = os.environ.get(name, "").strip()
    if not value:
        if required:
            fail(f"Missing required setting: {name}")
        return default
    return value


def parse_shapes(raw):
    """'2:12,1:6' -> [(2.0, 12.0), (1.0, 6.0)]"""
    shapes = []
    try:
        for part in raw.split(","):
            if part.strip():
                ocpus, mem = part.strip().split(":")
                shapes.append((float(ocpus), float(mem)))
    except ValueError:
        fail("SHAPE_CONFIGS must look like '2:12,1:6'")
    if not shapes:
        fail("SHAPE_CONFIGS is empty")
    return shapes


TENANCY = env("OCI_TENANCY_OCID", required=True)
OCI_CONFIG = {
    "user": env("OCI_USER_OCID", required=True),
    "tenancy": TENANCY,
    "fingerprint": env("OCI_FINGERPRINT", required=True),
    "key_content": env("OCI_PRIVATE_KEY", required=True),
    "region": env("OCI_REGION", "ap-mumbai-1"),
}
if env("OCI_KEY_PASSPHRASE"):
    OCI_CONFIG["pass_phrase"] = env("OCI_KEY_PASSPHRASE")

COMPARTMENT = env("OCI_COMPARTMENT_OCID", TENANCY)
SSH_PUBLIC_KEY = env("SSH_PUBLIC_KEY", required=True)
if "PRIVATE KEY" in SSH_PUBLIC_KEY or not SSH_PUBLIC_KEY.startswith(("ssh-", "ecdsa-")):
    fail("SSH_PUBLIC_KEY must be the contents of your .pub file (starts with 'ssh-rsa'). "
         "It looks like a private key was pasted - never use the private key here.")

SUBNET_OCID = env("OCI_SUBNET_OCID")                  # auto-detected if empty
IMAGE_OCID = env("OCI_IMAGE_OCID")                    # auto-detected if empty
AVAILABILITY_DOMAIN = env("OCI_AVAILABILITY_DOMAIN")  # auto-detected if empty

SHAPE = env("SHAPE", "VM.Standard.A1.Flex")
# Tried in order on every attempt: biggest free size first, then smaller ones.
SHAPE_CONFIGS = parse_shapes(env("SHAPE_CONFIGS", "2:12,1:6"))
# Fixed shapes (e.g. VM.Standard.E2.1.Micro) take no size; try them once per attempt.
IS_FLEX = SHAPE.endswith(".Flex")
if not IS_FLEX:
    SHAPE_CONFIGS = [(0, 0)]
BOOT_VOLUME_GB = int(env("BOOT_VOLUME_GB", "100"))
DISPLAY_NAME = env("DISPLAY_NAME", "free-arm-server")
OS_NAME = env("OS_NAME", "Canonical Ubuntu")
OS_VERSION = env("OS_VERSION", "24.04")

RETRY_INTERVAL = int(env("RETRY_INTERVAL_SECONDS", "60"))
RUN_MINUTES = float(env("RUN_MINUTES", "13"))  # how long one run keeps trying

SMTP_HOST = env("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(env("SMTP_PORT", "465"))
SMTP_USER = env("SMTP_USER")
SMTP_PASS = env("SMTP_PASS")
EMAIL_TO = env("EMAIL_TO", SMTP_USER)

NO_RETRY = oci.retry.NoneRetryStrategy()

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def set_github_output(key, value):
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(f"{key}={value}\n")


def send_email(subject, body):
    if not (SMTP_USER and SMTP_PASS and EMAIL_TO):
        log("Email not configured (SMTP_USER / SMTP_PASS / EMAIL_TO) - skipping email.")
        return
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = SMTP_USER
    msg["To"] = EMAIL_TO
    msg.set_content(body)
    try:
        if SMTP_PORT == 465:
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=30) as s:
                s.login(SMTP_USER, SMTP_PASS)
                s.send_message(msg)
        else:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as s:
                s.starttls()
                s.login(SMTP_USER, SMTP_PASS)
                s.send_message(msg)
        log("Email sent.")
    except Exception as exc:  # never let email failure hide a created instance
        log(f"Email failed: {type(exc).__name__}: {exc}")


def is_capacity_error(err):
    return "capacity" in f"{err.code} {err.message}".lower()


def find_existing_instance(compute):
    instances = oci.pagination.list_call_get_all_results(
        compute.list_instances, compartment_id=COMPARTMENT, display_name=DISPLAY_NAME
    ).data
    for inst in instances:
        if inst.lifecycle_state not in ("TERMINATED", "TERMINATING"):
            return inst
    return None


def pick_availability_domain(identity):
    if AVAILABILITY_DOMAIN:
        return AVAILABILITY_DOMAIN
    ads = identity.list_availability_domains(compartment_id=TENANCY).data
    if not ads:
        fail("No availability domains found - check region / credentials.")
    mask(ads[0].name)
    return ads[0].name


def pick_subnet(network):
    if SUBNET_OCID:
        return SUBNET_OCID
    subnets = oci.pagination.list_call_get_all_results(
        network.list_subnets, compartment_id=COMPARTMENT, lifecycle_state="AVAILABLE"
    ).data
    public = [s for s in subnets if not s.prohibit_public_ip_on_vnic]
    # A public subnet is only reachable if its route table points at an internet gateway.
    usable = [s for s in public if has_internet_route(network, s.route_table_id)]
    if not usable:
        fail("No public subnet with an internet gateway found. In the OCI console: "
             "Networking > Virtual Cloud Networks > Start VCN Wizard > "
             "'Create VCN with Internet Connectivity'.")
    log(f"Internet-connected public subnet found ({len(usable)} available, using the first).")
    return usable[0].id


def has_internet_route(network, route_table_id):
    try:
        rules = network.get_route_table(route_table_id).data.route_rules or []
    except oci.exceptions.ServiceError:
        return False
    return any(r.network_entity_id and r.network_entity_id.startswith("ocid1.internetgateway")
               and r.destination == "0.0.0.0/0" for r in rules)


def pick_image(compute):
    if IMAGE_OCID:
        return IMAGE_OCID
    images = compute.list_images(
        compartment_id=COMPARTMENT,
        operating_system=OS_NAME,
        operating_system_version=OS_VERSION,
        shape=SHAPE,
        sort_by="TIMECREATED",
        sort_order="DESC",
    ).data
    preferred = [i for i in images if "minimal" not in i.display_name.lower()
                 and "gpu" not in i.display_name.lower()]
    chosen = (preferred or images or [None])[0]
    if chosen is None:
        fail(f"No image found for {OS_NAME} {OS_VERSION} on {SHAPE}. Set OCI_IMAGE_OCID.")
    log(f"Using image: {chosen.display_name}")  # public Oracle image name, not secret
    return chosen.id


def public_ip_of(compute, network, instance_id):
    atts = compute.list_vnic_attachments(
        compartment_id=COMPARTMENT, instance_id=instance_id
    ).data
    for att in atts:
        if att.lifecycle_state == "ATTACHED":
            vnic = network.get_vnic(att.vnic_id).data
            if vnic.public_ip:
                return vnic.public_ip
    return None


def wait_until_running(compute, instance_id, timeout=600):
    end = time.time() + timeout
    state = None
    while time.time() < end:
        state = compute.get_instance(instance_id).data.lifecycle_state
        if state in ("RUNNING", "TERMINATED", "TERMINATING"):
            return state
        time.sleep(10)
    return state


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #


def run():
    identity = oci.identity.IdentityClient(OCI_CONFIG)
    compute = oci.core.ComputeClient(OCI_CONFIG)
    network = oci.core.VirtualNetworkClient(OCI_CONFIG)

    if find_existing_instance(compute):
        log("Instance already exists. Nothing to do.")
        set_github_output("done", "true")
        return

    ad = pick_availability_domain(identity)
    subnet_id = pick_subnet(network)
    image_id = pick_image(compute)
    sizes = ", ".join(f"{o:g} OCPU/{m:g} GB" for o, m in SHAPE_CONFIGS) if IS_FLEX else "fixed size"
    log(f"Region {OCI_CONFIG['region']} | {SHAPE} | trying: {sizes}")

    deadline = time.time() + RUN_MINUTES * 60
    attempt = 0
    while True:
        attempt += 1
        wait = RETRY_INTERVAL
        limit_hits = 0

        for ocpus, mem in SHAPE_CONFIGS:
            size = f"{ocpus:g} OCPU/{mem:g} GB" if IS_FLEX else "fixed size"
            details = oci.core.models.LaunchInstanceDetails(
                compartment_id=COMPARTMENT,
                availability_domain=ad,
                display_name=DISPLAY_NAME,
                shape=SHAPE,
                shape_config=oci.core.models.LaunchInstanceShapeConfigDetails(
                    ocpus=ocpus, memory_in_gbs=mem
                ) if IS_FLEX else None,
                source_details=oci.core.models.InstanceSourceViaImageDetails(
                    image_id=image_id, boot_volume_size_in_gbs=BOOT_VOLUME_GB
                ),
                create_vnic_details=oci.core.models.CreateVnicDetails(
                    subnet_id=subnet_id, assign_public_ip=True
                ),
                metadata={"ssh_authorized_keys": SSH_PUBLIC_KEY},
            )
            try:
                inst = compute.launch_instance(details, retry_strategy=NO_RETRY).data
            except oci.exceptions.ServiceError as err:
                if is_capacity_error(err):
                    log(f"#{attempt} {size}: out of capacity")
                    time.sleep(3)
                    continue
                if err.status == 429:
                    log(f"#{attempt} rate limited (429) - backing off")
                    wait = RETRY_INTERVAL * 3
                    break
                if err.code == "LimitExceeded" or "limit" in (err.message or "").lower():
                    # Quota partly used elsewhere? A smaller size may still fit.
                    log(f"#{attempt} {size}: service limit exceeded")
                    limit_hits += 1
                    if limit_hits == len(SHAPE_CONFIGS):
                        send_email(
                            "OCI sniper stopped: limit exceeded",
                            f"Every size was refused with a limit error:\n{err.message}\n\n"
                            "You probably already use your free A1 quota on another instance.",
                        )
                        set_github_output("done", "true")
                        return
                    continue
                raise

            mask(inst.id)
            log(f"Launch accepted with {size}! Waiting for RUNNING...")
            state = wait_until_running(compute, inst.id)
            if state in ("TERMINATED", "TERMINATING"):
                log(f"Instance went to {state} (capacity reclaimed). Retrying.")
                continue

            ip = public_ip_of(compute, network, inst.id)
            mask(ip)
            ip_text = ip or "(not assigned yet - check the console)"
            log(f"SUCCESS: instance is {state}. Details sent by email (not logged).")
            send_email(
                "OCI instance created",
                f"Your Oracle Cloud instance is ready.\n\n"
                f"Name:      {DISPLAY_NAME}\n"
                f"Shape:     {SHAPE} ({size} RAM)\n"
                f"Region:    {OCI_CONFIG['region']}\n"
                f"State:     {state}\n"
                f"Public IP: {ip_text}\n"
                f"OCID:      {inst.id}\n\n"
                f"Connect:   ssh -i <your-private-key> ubuntu@{ip_text}\n"
                f"(Oracle Linux images use the user 'opc' instead of 'ubuntu'.)\n\n"
                f"The GitHub workflow will now disable itself.\n",
            )
            set_github_output("done", "true")
            return

        if time.time() + wait > deadline:
            log(f"No capacity this run ({attempt} attempt(s)). Next scheduled run will retry.")
            return
        time.sleep(wait)


def main():
    # Never let a raw traceback reach the log: OCI errors embed OCIDs and URLs.
    try:
        run()
    except oci.exceptions.ServiceError as err:
        hint = ""
        if err.status in (401, 404):
            hint = " (check OCI_USER_OCID / OCI_TENANCY_OCID / OCI_FINGERPRINT / OCI_PRIVATE_KEY and policies)"
        fail(describe_error(err) + hint)
    except oci.exceptions.InvalidConfig as err:
        fields = err.args[0] if err.args and isinstance(err.args[0], dict) else {}
        fail(f"Invalid OCI config, check these secrets: {', '.join(fields) or 'unknown'}")
    except Exception as err:
        fail(f"{type(err).__name__}: {err}")


if __name__ == "__main__":
    main()

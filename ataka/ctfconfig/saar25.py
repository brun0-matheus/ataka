from pwn import *
import json
import requests
import enum

class FlagStatus(str, enum.Enum):
    UNKNOWN = 'unknown'

    # Flag yielded points
    OK = 'ok'

    # Flag is in queue for submission
    QUEUED = 'queued'

    # Flag is currently being submitted
    PENDING = 'pending'

    # We already submitted this flag and the submission system tells us that
    DUPLICATE = 'duplicate'

    # We didn't submit this flag because it was a duplicate
    DUPLICATE_NOT_SUBMITTED = "duplicate_not_submitted"

    # something is wrong with our submitter or the flag service
    ERROR = 'error'

    # the flag belongs to the NOP team
    NOP = 'NOP'

    # we tried to submit our own flag and the submission system lets us know
    OWNFLAG = 'ownflag'

    # the flag is not longer active. This is used if a flags expire
    INACTIVE = 'inactive'

    # flag fits the format and could be sent to the submission system, but the
    # submission system told us it is invalid
    INVALID = 'invalid'

FLAG_SUBMIT_HOST = "submission.ctf.saarland"
FLAG_SUBMIT_PORT = 31337

# Ataka Host Domain / IP
ATAKA_HOST = "localhost"

# Our own host
OWN_HOST = "10.32.45.2"

RUNLOCAL_TARGETS = ["10.32.1.2"]  

# Config for framework
ROUND_TIME = 120  # TODO: they said 2-3 min,

# format: regex, group where group 0 means the whole regex
FLAG_REGEX = r"SAAR\{[A-Za-z0-9_-]{32}\}", 0

FLAG_BATCHSIZE = 400

FLAG_RATELIMIT = 5  # Wait in seconds between each call of submit_flags()

START_TIME = 1762606800 + 1

# IPs that are always excluded from attacks.
STATIC_EXCLUSIONS = set([OWN_HOST])

SERVICE_NAMES = ['blockrope', 'calendar', 'Licenser', 'no-service', 'RCEaaS', 'Routerploit', 'saarlandcryptogalore', 'SSSG']

# End config


def get_services() -> list:
    return SERVICE_NAMES


def get_targets() -> dict:
    additional_services = ['blockrope', 'calendar', 'saarlandcryptogalore']  # TODO: services with no flag id 
    targets = {}

    dt = requests.get('https://scoreboard.ctf.saarland/api/attack.json').json()

    teams = [t['ip'] for t in dt['teams']]
    for service, atk_info in dt['flag_ids'].items():
        targets[service] = []

        for ip, ids in atk_info.items():
            extra = [extra_round for flag_round, extra_round in ids.items()]
            # I'm not sure if the key actually is the flag round 

            targets[service].append({'ip': ip, 'extra': json.dumps(extra)})

    for service in additional_services:
        targets[service] = [{'ip': ip, 'extra': '[]'} for ip in teams]

    return targets

def submit_flags(flags) -> list:
    results = []
    try:
        server = remote(FLAG_SUBMIT_HOST, FLAG_SUBMIT_PORT, timeout=5)
        server.sendline('\n'.join(flags).encode())
        for _ in flags:
            response = server.recvline(timeout=5).upper()
            if b"OK" in response:
                results += [FlagStatus.OK]
            elif b"INVALID FLAG" in response:
                results += [FlagStatus.INVALID]
            elif b"ALREADY SUBMITTED" in response:
                results += [FlagStatus.DUPLICATE]
            elif b"EXPIRED" in response:
                results += [FlagStatus.INACTIVE]
            elif b"OWN FLAG" in response:
                results += [FlagStatus.OWNFLAG]
            elif b'NOP TEAM' in response:
                results += [FlagStatus.NOP]
            else:
                results += [FlagStatus.ERROR]
                print(f"Invalid response: {response}")
        server.close()
    except Exception as e:
        print(f"Exception: {e}", flush=True)
        results += [FlagStatus.ERROR for _ in flags[len(results):]]

    return results


if __name__ == "__main__":
    import pprint

    pp = pprint.PrettyPrinter(indent=4)
    pp.pprint(get_targets().keys())
    '''pp.pprint(
        submit_flags(
            [
                "ENOBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "ENOBCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "jou",
            ]
        )
    )'''

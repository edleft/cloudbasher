"""Realistic-looking usernames for redaction pseudonyms."""

from __future__ import annotations


FIRST_NAMES: tuple[str, ...] = (

    "james",
    "john",
    "mary",
    "sarah",
    "david",
    "emma",
    "chris",
    "laura",
    "peter",
    "alice",
    "thomas",
    "grace",
    "henry",
    "olivia",
    "jack",
    "chloe",
    "ryan",
    "megan",
    "scott",
    "holly",
    "brian",
    "karen",
    "alan",
    "diane",
    "gavin",
    "paula",
    "neil",
    "tracy",
    "glen",
    "wendy",
    "craig",
    "ellen",
    "kyle",
    "nora",
    "brett",

    "pierre",
    "marie",
    "hans",
    "greta",
    "luca",
    "sofia",
    "mateo",
    "elena",
    "jan",
    "anna",
    "piotr",
    "magda",
    "ivan",
    "olga",
    "nikola",
    "mila",
    "andrei",
    "ioana",
    "lars",
    "ingrid",
    "sven",
    "freja",
    "dirk",
    "anouk",
    "joao",
    "ines",
    "pablo",
    "lucia",
    "marco",
    "giulia",
    "sergei",
    "katya",
    "tomas",
    "zuzana",
    "bojan",

    "hochan",
    "jisoo",
    "minjun",
    "yuna",
    "haruto",
    "sakura",
    "kenji",
    "aiko",
    "wei",
    "mei",
    "jian",
    "lin",
    "ravi",
    "priya",
    "arjun",
    "neha",
    "siti",
    "budi",
    "linh",
    "thao",
    "hyun",
    "jimin",
    "takeshi",
    "yui",
    "chen",
    "xia",
    "rahul",
    "anita",
    "kiran",
    "dewi",
)


LAST_NAMES: tuple[str, ...] = (

    "smith",
    "jones",
    "brown",
    "davis",
    "wilson",
    "taylor",
    "clark",
    "harris",
    "lewis",
    "walker",
    "hall",
    "allen",
    "young",
    "king",
    "wright",
    "gray",
    "green",
    "baker",
    "adams",
    "nelson",
    "hill",
    "carter",
    "moore",
    "ward",
    "cole",
    "bell",
    "reed",
    "cook",
    "bailey",
    "murphy",
    "kelly",
    "shaw",
    "price",
    "quinn",
    "hayes",

    "muller",
    "schmidt",
    "weber",
    "fischer",
    "meyer",
    "wagner",
    "becker",
    "rossi",
    "russo",
    "ferrari",
    "bruno",
    "greco",
    "conti",
    "ricci",
    "garcia",
    "lopez",
    "martin",
    "sanchez",
    "perez",
    "gomez",
    "ruiz",
    "silva",
    "costa",
    "sousa",
    "dubois",
    "moreau",
    "laurent",
    "petit",
    "roux",
    "novak",
    "kowal",
    "horvat",
    "popov",
    "ivanov",
    "dvorak",

    "park",
    "kim",
    "lee",
    "choi",
    "jung",
    "kang",
    "yoon",
    "tanaka",
    "sato",
    "suzuki",
    "kato",
    "mori",
    "wang",
    "zhang",
    "liu",
    "yang",
    "huang",
    "patel",
    "singh",
    "kumar",
    "nair",
    "desai",
    "gupta",
    "nguyen",
    "tran",
    "pham",
    "putra",
    "tan",
    "lim",
    "cheng",
)


_INITIALS: tuple[str, ...] = tuple(sorted({n[0] for n in FIRST_NAMES}))


SHORT_FORM_COUNT = len(_INITIALS) * len(LAST_NAMES)
FULL_FORM_COUNT = len(FIRST_NAMES) * len(LAST_NAMES)
CAPACITY = SHORT_FORM_COUNT + FULL_FORM_COUNT


_STRIDE = 3719


def username_for(idx: int) -> str:
    """The `idx`-th username pseudonym. Deterministic, injective, never empty."""
    if idx < 0:
        idx = 0
    cycle, within = divmod(idx, CAPACITY)
    if within < SHORT_FORM_COUNT:
        scattered = (within * _STRIDE) % SHORT_FORM_COUNT
        name = (
            f"{_INITIALS[scattered // len(LAST_NAMES)]}"
            f"{LAST_NAMES[scattered % len(LAST_NAMES)]}"
        )
    else:
        pair = within - SHORT_FORM_COUNT
        scattered = (pair * _STRIDE) % FULL_FORM_COUNT
        name = (
            f"{FIRST_NAMES[scattered // len(LAST_NAMES)]}."
            f"{LAST_NAMES[scattered % len(LAST_NAMES)]}"
        )
    return name if cycle == 0 else f"{name}{cycle}"


ROLE_SERVICES: tuple[str, ...] = (
    "Bucket",
    "S3",
    "RDS",
    "Lambda",
    "EC2",
    "IAM",
    "Glue",
    "Kinesis",
    "Athena",
    "Dynamo",
    "ECS",
    "EKS",
    "SQS",
    "SNS",
    "CloudWatch",
    "Redshift",
    "Secrets",
    "KMS",
    "Route53",
    "CloudFront",
    "StepFn",
    "Batch",
    "EMR",
    "Sagemaker",
    "Config",
)


ROLE_ACTIONS: tuple[str, ...] = (
    "Admin",
    "User",
    "Owner",
    "Read",
    "Writer",
    "Auditor",
    "Operator",
    "Deploy",
    "Support",
    "Analyst",
    "Backup",
    "Viewer",
)

_TAIL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_TAIL_SPAN = len(_TAIL_ALPHABET) ** 3


ROLE_CAPACITY = len(ROLE_SERVICES) * len(ROLE_ACTIONS) * _TAIL_SPAN


_ROLE_STRIDE = 5_100_487


def role_for(idx: int) -> str:
    """The `idx`-th role-name pseudonym. Deterministic, injective, never empty."""
    if idx < 0:
        idx = 0
    cycle, within = divmod(idx, ROLE_CAPACITY)
    scattered = (within * _ROLE_STRIDE) % ROLE_CAPACITY


    rest, tail_n = divmod(scattered, _TAIL_SPAN)
    action = ROLE_ACTIONS[rest % len(ROLE_ACTIONS)]
    service = ROLE_SERVICES[(rest // len(ROLE_ACTIONS)) % len(ROLE_SERVICES)]
    tail = "".join(_TAIL_ALPHABET[(tail_n // 26**p) % 26] for p in (2, 1, 0))
    name = f"{service}{action}{tail}"
    return name if cycle == 0 else f"{name}{cycle}"


COMPANY_NAMES: tuple[str, ...] = (
    "acme",
    "globex",
    "initech",
    "umbrella",
    "soylent",
    "hooli",
    "vandelay",
    "wonka",
    "cyberdyne",
    "tyrell",
    "wayne",
    "stark",
    "aperture",
    "abstergo",
    "weyland",
    "nakatomi",
    "gringotts",
    "duff",
    "bluth",
    "prestige",
    "sterling",
    "pierce",
    "dunder",
    "vehement",
    "zenith",
    "apex",
    "summit",
    "beacon",
    "harbor",
    "meridian",
    "quarry",
    "lattice",
    "kestrel",
    "onyx",
    "verdant",
    "cobalt",
    "juniper",
    "sable",
    "thorn",
    "vector",
)

COMPANY_CAPACITY = len(COMPANY_NAMES)


def company_for(idx: int) -> str:
    """The `idx`-th company pseudonym. Deterministic, injective, never empty."""
    if idx < 0:
        idx = 0
    cycle, within = divmod(idx, COMPANY_CAPACITY)
    name = COMPANY_NAMES[within]
    return name if cycle == 0 else f"{name}{cycle}"

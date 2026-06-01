"""
Utility functions
"""

import ipaddress
from typing import List
from colorama import init, Fore, Style

init(autoreset=True)


def print_banner():
    """
    BUSHIDO banner — rectangle frame, oni mask center, virtues left/right.
    Total width: 78 chars inside the border.
    Left col: 20 chars | gap: 1 | Center: 34 chars | gap: 1 | Right col: 20 chars = 76 + 2 borders = 78
    """
    R  = Fore.RED
    W  = Fore.WHITE
    G  = Fore.GREEN + Style.BRIGHT
    D  = Style.DIM + Fore.WHITE
    Y  = Fore.YELLOW
    RS = Style.RESET_ALL
    B  = Style.BRIGHT

    # ── Oni mask + torii gate + rising sun — 34 chars wide exactly ────────
    # Each line is exactly 34 characters
    face = [
        #          1234567890123456789012345678901234
        "                                  ",  # 0
        "         .-------------.          ",  # 1  sun top
        "       .'  = = = = = =  '.        ",  # 2  sun stripes
        "      /  = = = = = = = =  \\      ",  # 3
        "     | _____         _____ |      ",  # 4  torii top bar
        "     |/     \\       /     \\|     ",  # 5  torii arch
        "     ||  |  |       |  |  ||      ",  # 6  torii pillars
        "     ||__|__|_______|__|__||      ",  # 7  torii base
        "     |   /\\  _____  /\\   |      ",  # 8  kabuto horns
        "     |  /  \\/     \\/  \\  |     ",  # 9
        "     | | .--(  *  )--. | |       ",  # 10 kabuto gem
        "     | |/   |_____|   \\| |       ",  # 11 kabuto helmet
        "     | |  ___________  | |       ",  # 12
        "     |_| /           \\ |_|      ",  # 13 helmet sides
        "     |  |  .--------.  |  |      ",  # 14 face frame
        "     |  | | (o)  (o) | |  |      ",  # 15 ONI EYES
        "     |  | |    __    | |  |      ",  # 16
        "     |  | |   /  \\   | |  |     ",  # 17 oni nose
        "     |  | |  | /\\ |  | |  |     ",  # 18
        "     |  |  \\ |____| /  |  |     ",  # 19 oni mouth top
        "     |  |  /|V    V|\\  |  |     ",  # 20 fangs
        "     |  | / |  __  | \\ |  |     ",  # 21
        "     |  |/  |______|  \\|  |     ",  # 22 chin
        "     |   \\____________/   |      ",  # 23 neck guard
        "     |    |          |    |      ",  # 24 shoulder
        "      \\   |__________|   /       ",  # 25
        "       '.              .'        ",  # 26 sun bottom
        "         '------------'          ",  # 27
        "                                  ",  # 28
        "    * * * B U S H I D O * * *    ",  # 29
        "                                  ",  # 30
        "   ------------------------------ ",  # 31
        "                                  ",  # 32
    ]
    # Enforce exactly 34 chars
    face = [line.ljust(34)[:34] for line in face]
    H = len(face)

    # ── Virtue data ───────────────────────────────────────────────────────
    # Left: 4 virtues, Right: 3 virtues — each block = 4 lines (blank+code+name+desc)
    # Column width = 20 chars
    CW = 20

    left_virtues = [
        ("GI",    "INTEGRITY",  "Honest in all"),
        ("REI",   "RESPECT",    "Courteous to all"),
        ("YU",    "COURAGE",    "Brave and bold"),
        ("MEYO",  "HONOR",      "Judge yourself"),
    ]
    right_virtues = [
        ("JIN",    "COMPASSION", "Power for good"),
        ("MAKOTO", "SINCERITY",  "Word = action"),
        ("CHUGI",  "LOYALTY",    "Faithful always"),
    ]

    def build_col(virtues, width, align, height):
        """Spread virtues evenly across `height` rows. Each virtue = 4 rows."""
        rows = [(" " * width, "blank")] * height
        # Each virtue takes 4 rows: blank, code, name, desc
        block = 4
        n_virtues = len(virtues)
        total_virtue_rows = n_virtues * block
        gap = max(1, (height - total_virtue_rows) // (n_virtues + 1))

        pos = gap
        for code, name, desc in virtues:
            tag = f"[{code:^6}]"
            if align == "right":
                entries = [
                    (" " * width,           "blank"),
                    (tag.rjust(width)[:width],  "code"),
                    (name.rjust(width)[:width], "name"),
                    (desc.rjust(width)[:width], "desc"),
                ]
            else:
                entries = [
                    (" " * width,           "blank"),
                    (tag.ljust(width)[:width],  "code"),
                    (name.ljust(width)[:width], "name"),
                    (desc.ljust(width)[:width], "desc"),
                ]
            for e in entries:
                if pos < height:
                    rows[pos] = e
                    pos += 1
        return rows

    left_col  = build_col(left_virtues,  CW, "right", H)
    right_col = build_col(right_virtues, CW, "left",  H)

    # ── Inner width = CW + 1 + 34 + 1 + CW = 76, border adds 2 = 78 ─────
    IW = CW + 1 + 34 + 1 + CW  # = 76

    def border_line(char="-"):
        return f"  +{char * IW}+"

    def blank_line():
        return f"  |{' ' * IW}|"

    def center_text(text, color=""):
        pad = (IW - len(text)) // 2
        extra = IW - len(text) - pad
        if color:
            return f"  |{' ' * pad}{color}{text}{RS}{' ' * extra}|"
        return f"  |{' ' * pad}{text}{' ' * extra}|"

    # ── Print header ──────────────────────────────────────────────────────
    print()
    print(f"{R}{border_line('=')}{RS}")
    print(f"{R}|{W}{B}{'T H E   W A Y   O F   T H E   S A M U R A I':^{IW}}{RS}{R}|{RS}")
    print(f"{R}{border_line('=')}{RS}")

    # ── Print body rows ───────────────────────────────────────────────────
    for i in range(H):
        lt, ls = left_col[i]
        if ls == "code":
            lstr = f"{R}{B}{lt}{RS}"
        elif ls == "name":
            lstr = f"{W}{B}{lt}{RS}"
        elif ls == "desc":
            lstr = f"{G}{lt}{RS}"
        else:
            lstr = lt  # plain spaces — no ANSI to avoid width issues

        cl = face[i]
        if "BUSHIDO" in cl:
            cstr = f"{W}{B}{cl}{RS}"
        elif "=" in cl and ("." in cl or "'" in cl):
            cstr = f"{R}{cl}{RS}"
        elif cl.strip().startswith("*"):
            cstr = f"{R}{cl}{RS}"
        elif cl.strip().startswith("-"):
            cstr = f"{R}{cl}{RS}"
        elif "(o)" in cl:
            cstr = f"{R}{B}{cl}{RS}"   # oni eyes — red bright
        elif "V" in cl and "V" in cl[cl.index("V")+1:]:
            cstr = f"{W}{cl}{RS}"      # fangs
        elif ".-" in cl or "-." in cl:
            cstr = f"{Y}{cl}{RS}"      # kabuto gem line
        else:
            cstr = f"{W}{cl}{RS}"

        rt, rs = right_col[i]
        if rs == "code":
            rstr = f"{R}{B}{rt}{RS}"
        elif rs == "name":
            rstr = f"{W}{B}{rt}{RS}"
        elif rs == "desc":
            rstr = f"{G}{rt}{RS}"
        else:
            rstr = rt

        print(f"{R}|{RS}{lstr} {cstr} {rstr}{R}|{RS}")

    # ── Footer ────────────────────────────────────────────────────────────
    print(f"{R}{border_line('=')}{RS}")
    tagline    = "BUSHIDO v0.0.1  |  Inspired by Good For GooD  |  AI AUTOMATED RED TEAM TOOLKIT"
    disclaimer = "FOR EDUCATIONAL PURPOSES ONLY  /  FOR AUTHORIZED PROFESSIONALS"
    print(f"{R}|{RS}{W}{B}{tagline:^{IW}}{RS}{R}|{RS}")
    print(f"{R}|{RS}{Style.DIM}{Fore.WHITE}{disclaimer:^{IW}}{RS}{R}|{RS}")
    print(f"{R}{border_line('=')}{RS}")
    print()


def print_goodbye():
    """
    Goodbye message — shows all 7 Bushido virtues with kanji.
    """
    R  = Fore.RED
    W  = Fore.WHITE
    G  = Fore.GREEN + Style.BRIGHT
    Y  = Fore.YELLOW + Style.BRIGHT
    D  = Style.DIM + Fore.WHITE
    RS = Style.RESET_ALL
    B  = Style.BRIGHT

    virtues = [
        ("GI",     "GI",    "INTEGRITY",  "Honest in all things."),
        ("REI",    "REI",   "RESPECT",    "Courteous to all."),
        ("YU",     "YU",    "COURAGE",    "Brave and bold."),
        ("MEYO",   "MEYO",  "HONOR",      "Judge yourself."),
        ("JIN",    "JIN",   "COMPASSION", "Power used for good."),
        ("MAKOTO", "MAKO",  "SINCERITY",  "Word equals action."),
        ("CHUGI",  "CHUGI", "LOYALTY",    "Faithful to the end."),
    ]

    sep = "-" * 62
    print()
    print(f"  {R}{sep}{RS}")
    print(f"  {W}{B}  Don't forget the Bushido Virtues before you exit.{RS}")
    print(f"  {D}  I'll see you next time, warrior.{RS}")
    print(f"  {R}{sep}{RS}")
    print()
    print(f"  {D}  {'CODE':<8} {'NAME':<12} {'MEANING'}{RS}")
    print(f"  {R}  {'-'*6}  {'-'*11}  {'-'*28}{RS}")
    for code, _, name, desc in virtues:
        print(
            f"  {R}[{code:^6}]{RS}  "
            f"{W}{B}{name:<12}{RS}  "
            f"{G}{desc}{RS}"
        )
    print()
    print(f"  {R}{sep}{RS}")
    print(f"  {D}  The way of the warrior lives on.  -- BUSHIDO{RS}")
    print(f"  {R}{sep}{RS}")
    print()


def parse_targets(target_spec: str) -> List[str]:
    """
    Parse target specification into list of IP addresses / hostnames.
    Accepts:
      - Full URLs:   http://example.com/path  https://example.com:8080/path
      - Hostname:    example.com
      - IP:          192.168.1.1
      - IP range:    192.168.1.1-10
      - CIDR:        192.168.1.0/24
    """
    import socket

    target_spec = target_spec.strip()

    # ── Strip URL scheme and path if a full URL is given ─────────────────
    # e.g. http://challenge01.root-me.org/web-serveur/ch9/
    #   → challenge01.root-me.org
    if '://' in target_spec:
        # Remove scheme
        without_scheme = target_spec.split('://', 1)[1]
        # Remove path (everything after first /)
        host_part = without_scheme.split('/')[0]
        # Remove port if present
        host_part = host_part.split(':')[0]
        target_spec = host_part.strip()

    targets = []
    try:
        # IP range: 192.168.1.1-10
        if '-' in target_spec and '/' not in target_spec:
            parts = target_spec.split('-')
            if len(parts) == 2:
                base_ip   = parts[0]
                end_range = int(parts[1])
                ip_parts  = base_ip.split('.')
                if len(ip_parts) == 4:
                    start_range = int(ip_parts[3])
                    base        = '.'.join(ip_parts[:3])
                    for i in range(start_range, end_range + 1):
                        targets.append(f"{base}.{i}")
                    return targets

        # CIDR: 192.168.1.0/24
        if '/' in target_spec:
            network = ipaddress.ip_network(target_spec, strict=False)
            targets = [str(ip) for ip in network.hosts()]
            return targets

        # Single IP
        ipaddress.ip_address(target_spec)
        targets.append(target_spec)

    except ValueError:
        # Hostname — resolve to IP
        try:
            ip = socket.gethostbyname(target_spec)
            targets.append(ip)
        except socket.gaierror:
            return []

    return targets


def parse_ports(port_spec: str) -> List[int]:
    """Parse port specification into list of ports"""
    ports = []
    try:
        specs = port_spec.split(',')
        for spec in specs:
            spec = spec.strip()
            if '-' in spec:
                start, end = spec.split('-')
                start = int(start.strip())
                end   = int(end.strip())
                if start < 1 or end > 65535 or start > end:
                    continue
                ports.extend(range(start, end + 1))
            else:
                port = int(spec)
                if 1 <= port <= 65535:
                    ports.append(port)
        ports = sorted(list(set(ports)))
    except ValueError:
        return []
    return ports

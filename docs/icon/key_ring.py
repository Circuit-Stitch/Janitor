"""
Key ring model for the Janitor app icon.

Builds a ring with skeleton keys hanging from it, then renders a square PNG with
a transparent background.

Run it headless:

    blender -b -P key_ring.py -- --render --sizes --save

Flags: --render writes renders/icon-1024.png, --sizes downsamples that into the
icon set packaging consumes, --save writes key_ring.blend. Use --size and
--samples to trade quality for speed while iterating, and --keys to try a
different count without editing the file. --nest N builds a central ring with N
of these bunches hanging on it, instead of one bunch on its own.

Or open Blender, load this file in the Text Editor, and press Run Script. The
model appears in the viewport with no render.

Geometry comes from KEYS below. Each entry is one key. A key picks its bow
shape, bit cut pattern, shank ornament, and tip from the libraries further down,
so the keys in a fan differ from each other.

Where a key ends up is solved, not listed. The bows thread onto the wire as
beads. Each one sinks until it rests on the wire, then slides along it toward
the key beside it until their metal meets. A bunch therefore ends up as tight as
its own keys allow, and raising KEY_COUNT spreads the fan further around the
ring instead of piling keys on top of each other.

Units: the ring centerline radius is 1.0, or larger when a big bunch needs
more wire than that holds.
"""

import bpy
import bmesh
import math
import sys
import os
from mathutils import Matrix, Vector

# ──────────────────────────────────────────────────────────────────────────
# Key table — the editing surface
# ──────────────────────────────────────────────────────────────────────────
# Every angle here is a preference. The solver honors it when there is room and
# overrides it when there is not.
#
# hang_deg   Where the bow would like to sit on the ring. 0 is the ring's right
#            edge and the angle runs counterclockwise, so -90 is the bottom.
# tilt_deg   Lean away from straight down. Positive swings the tip right. A
#            key keeps this lean wherever its bead ends up on the wire.
# flare_deg  Lean out of the picture plane. Positive swings the tip away from
#            the camera. This sets which key laps over which.
# length     Bow center to tip.
# bow_r      Bow size. Every shape scales off it.
# bow        Bow shape, named in BOW_SHAPES.
# bit        Bit cut pattern, named in BIT_PATTERNS.
# bit_w      Bit reach, as a multiple of BIT_W.
# shank      Shank ornament, named in shank_beads.
# tip        Tip treatment: dome, bore, or flat.
# stub       Length of shaft past the bit, as a multiple of TIP_LEN.
# bit_side   Which way the bit points. -1 is left, +1 is right.
# tilt_side  Which way the key leans out of the ring's plane. Every key leans
#            the same way. Alternating them looks like it would separate
#            neighbors, but it does the opposite: the right edge of one bow and
#            the left edge of the next then land at the same depth, and they cut
#            through each other.

# The fan is generated, not hand placed. Raise KEY_COUNT to add keys; they
# redistribute across the same span. Edit or append to KEYS afterwards to move
# any single key by hand.

KEY_COUNT = 5
HANG_SPAN = 126.0        # degrees of ring the fan is laid out across
TILT_GAIN = 0.52         # how hard the keys splay away from vertical
LENGTH_BASE = 1.90       # length of a key hanging at the bottom
LENGTH_GROW = 0.55       # extra length toward the edges of the fan
LENGTH_JITTER = 0.10     # how far a key's length wanders off its designed one
BIT_W_JITTER = 0.10      # how far a bit's reach wanders off a full-width bit
BOW_BASE = 0.330
BOW_GROW = 0.060         # bows swell toward the middle of the fan
FLARE_SPAN = 15.0        # degrees of front to back lean across the fan
BOW_TILT_DEG = 52.0      # how far a key's plane leans out of the ring's plane
BOW_TILT_SIDE = 1        # which way it leans. Every key leans the same way.

# Settling. HANG_SPAN and TILT_GAIN lay the fan out; these close it up.
#
# The layout is a starting point, not the answer. Every key keeps the lean it
# was laid out with, but its bead slides along the wire until its metal meets
# the key beside it, so the span the bunch ends on is the one its own keys
# leave. Set SETTLE_DRAW to zero to have the keys stay where they were laid out
# and only move when they overlap.
BEAD_MARGIN = 1.25       # slack on the arc of wire a bow claims
CONTACT_SLACK = 0.0015   # daylight the solver leaves where metal comes to rest
FAN_MAX = 290.0          # most of the ring a fan may wrap, leaving the joint clear
SETTLE_PASSES = 40       # relaxation passes per settling run
SETTLE_PUSH = 0.55       # fraction of an overlap two keys slide apart per pass
SETTLE_PULL = 0.10       # fraction of the way back to the designed fan per pass
SETTLE_DRAW = 0.30       # fraction of the daylight beside a key that closes per pass
DRAW_REACH = 0.30        # furthest daylight a key measures beside it, and so
                         # the most of one gap a single pass can close
LINK_PUSH = 0.30         # how hard two keys threaded together are driven apart
DROP_STEP = 3.0          # degrees of twist between samples of the bow drop table
TWIST_MAX = 75.0         # furthest a bow is ever asked to twist off the wire
GROW_LEAST = 1.02        # smallest and largest step the ring grows by when the
GROW_MOST = 1.40         # fan runs out of wire, so sizing converges either way
GROW_TRIES = 12

# Bunches of bunches. A small ring hanging on a big one is the same problem as
# a bow hanging on a ring, so a whole settled bunch is handed to the same solver
# as one more thing to hang. NEST_TURN is not a free choice: each bunch is turned
# by exactly the angle its own keys were turned by, the other way, so the two
# cancel and the keys come back square to the camera.
NEST_COUNT = 3           # small rings on the central one
NEST_KEYS = 5            # keys on each small ring
NEST_WIRE_R = 0.078      # the central ring is heavier stock than a small one
NEST_SCALE = 1.45        # and this much bigger than the small rings it carries
NEST_SPAN = 150.0        # degrees of the central ring the small rings are laid across
NEST_TILT_GAIN = 0.45    # how hard the small rings splay away from vertical
NEST_FLARE = 12.0        # degrees of front to back lean across the small rings
NEST_GROUP = 32          # rods per bounding group in a bunch, coarser than a
                         # key's because a bunch is tested as one thing
NEST_STRAND = 24         # points per strand when asking whether bunches thread
NEST_POLY = 8            # every nth point of a small ring, as the hole to thread

# Style cycles. A key takes its style from its index, so a fan of any size keeps
# neighbors different. Reorder a cycle to change which key gets what.
BOW_CYCLE = ("trefoil", "round", "heart", "oval", "plate", "quatrefoil", "pear")
BIT_CYCLE = ("comb3", "ward", "comb2", "step", "fine")
SHANK_CYCLE = ("banded", "plain", "double", "plain", "banded")
TIP_CYCLE = ("dome", "dome", "bore", "dome", "flat")
STUB_CYCLE = (1.0, 0.7, 1.35, 0.85, 1.15)
BOW_SIZE_CYCLE = (1.00, 0.87, 1.13, 0.94, 1.06)

GOLDEN = 0.6180339887498949   # the step that spreads a short run most evenly


def wander(i, span, phase=0.0):
    """
    A repeatable nudge in [-span, span], different for every key.

    Alternating the sign of a nudge puts every key on one of two extremes, so a
    wide setting reads as two lengths of key rather than as a fan of many.
    Stepping by the golden ratio and keeping the fraction lands the keys all
    through the range instead, and still leaves no two neighbors alike. Give a
    second use of it its own phase, or it tracks the first one exactly.
    """
    return span * (2.0 * (((i + 1) * GOLDEN + phase) % 1.0) - 1.0)


def make_keys(count=KEY_COUNT, phase=0, tag="", turn=False):
    """
    Fan `count` keys across the bottom of the ring.

    phase moves every key along the style cycles and the jitter, so two fans of
    the same size come out different. turn asks for keys that are square in
    their own plane rather than sheared, for a bunch that is turned back the
    other way when it is hung.
    """
    keys = []
    for i in range(count):
        cut = i + phase
        # c runs -0.5 to 0.5 across the fan, 0 at the bottom of the ring.
        c = (i / (count - 1) - 0.5) if count > 1 else 0.0
        hang = -90.0 + HANG_SPAN * c
        keys.append(dict(
            name=f"{tag}Key{i + 1:02d}",
            turn=turn,
            hang_deg=hang,
            tilt_deg=(hang + 90.0) * TILT_GAIN,
            flare_deg=FLARE_SPAN * c,
            length=(LENGTH_BASE + LENGTH_GROW * abs(c) * 2
                    + wander(cut, LENGTH_JITTER)),
            bow_r=((BOW_BASE + BOW_GROW * (1.0 - abs(c) * 2))
                   * BOW_SIZE_CYCLE[cut % len(BOW_SIZE_CYCLE)]),
            bit_side=-1 if c < 0 else 1,
            tilt_side=BOW_TILT_SIDE,
            bow=BOW_CYCLE[cut % len(BOW_CYCLE)],
            bit=BIT_CYCLE[cut % len(BIT_CYCLE)],
            bit_w=1.0 + wander(cut, BIT_W_JITTER, 0.37),
            shank=SHANK_CYCLE[cut % len(SHANK_CYCLE)],
            tip=TIP_CYCLE[cut % len(TIP_CYCLE)],
            stub=STUB_CYCLE[cut % len(STUB_CYCLE)],
        ))
    return keys


KEYS = make_keys()

RING_RADIUS = 1.0        # centerline
RING_WIRE_R = 0.052      # stock thickness

WIRE_R = 0.082           # bow stock radius, the same the whole way round
PLATE_THICK = 0.150      # thickness of a flat bow
PLATE_BAND = 0.144       # width of a flat bow's metal, hole edge to outer edge

SHAFT_R = 0.080          # shaft radius below the collar
SHAFT_TAPER = 0.86       # tip radius as a fraction of SHAFT_R
COLLAR_R = 0.118         # widest point of the collar under the bow
COLLAR_U = 0.055         # how far below the bow the collar sits
COLLAR_W = 0.046         # half the collar's height
BORE_R = 0.030           # hole up the middle of a bored tip
BORE_DEPTH = 0.20

BIT_LEN = 0.48           # bit length along the shaft
BIT_W = 0.38             # how far the bit reaches out from the shaft
BIT_THICK = 0.064        # bit plate thickness
BIT_BEVEL = 0.018        # chamfer around the bit, so its edges catch light
TIP_LEN = 0.16           # stub of shaft past the bit

FERRULE_R = 0.072        # sleeve over the ring's joint, at the top
FERRULE_LEN = 0.20

JOIN = 0.020             # overlap where parts meet, so unions never gap

ICON_SIZES = (16, 24, 32, 48, 64, 128, 256, 512)

BOW_SEG = 72             # samples around a bow outline
MIN_SEG = 16             # segments around round stock
SHANK_SEG = 96           # samples down a shank profile

# Collision rods per part. A rod holds the metal between two samples exactly,
# so these set how closely a chain follows a curve, not how fat it reads. Set
# them at or above the counts the mesh itself is built from and the model stops
# approximating: a rod per drawn segment is the drawn segment.
BOW_RODS = 72
SHANK_RODS = 56
BIT_RODS = 64
PLATE_RODS = 3.0         # rods across a plate bow's band, per its own thickness
GROUP_SIZE = 8           # rods per bounding group

BRASS = (0.400, 0.250, 0.072, 1.0)   # linear, about #aa894c on screen

# Each object takes one patina: BRASS scaled by a tint, at its own roughness.
# Neighboring keys land on different entries, which is what makes the fan read
# as separate keys rather than one casting.
PATINA = ((1.00, 0.35), (0.74, 0.46), (1.22, 0.27))


# ──────────────────────────────────────────────────────────────────────────
# Mesh primitives
# ──────────────────────────────────────────────────────────────────────────

def _face(bm, verts):
    """Add a face, skipping any that duplicates one already built."""
    try:
        bm.faces.new(verts)
    except ValueError:
        pass


def flat(loop, matrix=None):
    """Lift a closed loop of (x, z) points into 3D, optionally moved."""
    return [matrix @ Vector((x, 0.0, z)) if matrix else Vector((x, 0.0, z))
            for x, z in loop]


def sweep(bm, path, r, face=Vector((0.0, 1.0, 0.0)), seg=MIN_SEG):
    """
    Sweep round stock along a closed planar path.

    The path is a list of 3D points lying in one plane, and face is that plane's
    normal. The cross-section is built from face and the path's own direction,
    so the stock stays round however the plane is turned, and never twists along
    the run.
    """
    n = len(path)
    rings = []
    for i in range(n):
        step = path[(i + 1) % n] - path[(i - 1) % n]
        across = face.cross(step)
        across = across.normalized() if across.length > 1e-9 else Vector((1.0, 0.0, 0.0))
        ring = []
        for j in range(seg):
            a = 2 * math.pi * j / seg
            v = path[i] + (across * math.cos(a) + face * math.sin(a)) * r
            ring.append(bm.verts.new(v))
        rings.append(ring)
    for i in range(n):
        ii = (i + 1) % n
        for j in range(seg):
            jj = (j + 1) % seg
            _face(bm, (rings[i][j], rings[ii][j], rings[ii][jj], rings[i][jj]))


def band(bm, outer, inner, thickness, face=Vector((0.0, 1.0, 0.0))):
    """
    Extrude the metal between two closed planar loops along their normal.

    Both loops are 3D and lie in the plane face is normal to, and both need the
    same point count and the same winding. Extruding along the normal rather
    than along a fixed axis keeps the plate the same thickness whichever way its
    plane is turned. The result is a flat plate with a hole through it.
    """
    lift = face * (thickness / 2)

    def row(loop, side):
        return [bm.verts.new(p + lift * side) for p in loop]

    ob, of = row(outer, -1), row(outer, 1)
    ib, if_ = row(inner, -1), row(inner, 1)
    for i in range(len(outer)):
        j = (i + 1) % len(outer)
        _face(bm, (ob[i], ob[j], of[j], of[i]))     # outer wall
        _face(bm, (ib[i], ib[j], if_[j], if_[i]))   # hole wall
        _face(bm, (ob[i], ib[i], ib[j], ob[j]))     # back face
        _face(bm, (of[i], if_[i], if_[j], of[j]))   # front face


def lathe(bm, profile, z0, seg=MIN_SEG, matrix=None):
    """
    Revolve an (r, u) profile around the Z axis, with u running down from z0.

    A profile point at r = 0 becomes a pole. Both ends of the profile must be
    poles or flat caps, so the surface closes.
    """
    rows = []
    for r, u in profile:
        z = z0 - u
        if r <= 1e-6:
            v = Vector((0.0, 0.0, z))
            rows.append([bm.verts.new(matrix @ v if matrix else v)])
            continue
        ring = []
        for j in range(seg):
            a = 2 * math.pi * j / seg
            v = Vector((r * math.cos(a), r * math.sin(a), z))
            if matrix:
                v = matrix @ v
            ring.append(bm.verts.new(v))
        rows.append(ring)
    for i in range(len(rows) - 1):
        a, b = rows[i], rows[i + 1]
        if len(a) == 1 and len(b) == 1:
            continue
        if len(a) == 1:
            for j in range(seg):
                _face(bm, (a[0], b[j], b[(j + 1) % seg]))
        elif len(b) == 1:
            for j in range(seg):
                _face(bm, (a[j], a[(j + 1) % seg], b[0]))
        else:
            for j in range(seg):
                jj = (j + 1) % seg
                _face(bm, (a[j], a[jj], b[jj], b[j]))


def prism(bm, poly, thickness, face=Vector((0.0, 1.0, 0.0))):
    """
    Extrude a closed planar loop along its normal, centered on the loop.

    poly is a list of 3D points lying in the plane face is normal to. Extruding
    along the normal rather than along a fixed axis keeps the plate the same
    thickness whichever way its plane is turned.
    """
    lift = face * (thickness / 2)
    back = [bm.verts.new(p - lift) for p in poly]
    front = [bm.verts.new(p + lift) for p in poly]
    n = len(poly)
    for i in range(n):
        j = (i + 1) % n
        _face(bm, (back[i], back[j], front[j], front[i]))
    _face(bm, tuple(reversed(back)))
    _face(bm, tuple(front))


# ──────────────────────────────────────────────────────────────────────────
# Bow shapes
# ──────────────────────────────────────────────────────────────────────────
# A bow is a closed outline in the key's local XZ plane, centered on its hole.
# Wire bows sweep round stock along that outline. Plate bows extrude the metal
# between an outer and an inner outline.

def _sample(fn, n=BOW_SEG):
    """Sample a closed parametric curve fn(t) -> (x, z) over one turn."""
    return [fn(2 * math.pi * i / n) for i in range(n)]


def _polar(radius_fn, n=BOW_SEG):
    """Sample a closed polar curve r(t) into (x, z) points."""
    return _sample(lambda t: (radius_fn(t) * math.cos(t),
                              radius_fn(t) * math.sin(t)), n)


def _recenter(loop):
    """Shift a loop so its bounding box centers on the origin."""
    xs = [p[0] for p in loop]
    zs = [p[1] for p in loop]
    cx = (min(xs) + max(xs)) / 2
    cz = (min(zs) + max(zs)) / 2
    return [(x - cx, z - cz) for x, z in loop]


def _rrect(hw, hh, cr, n=8):
    """Rounded rectangle of half-width hw and half-height hh, corner radius cr."""
    cr = max(min(cr, hw * 0.99, hh * 0.99), 1e-4)
    corners = ((hw - cr, hh - cr, 0.0),
               (-hw + cr, hh - cr, math.pi / 2),
               (-hw + cr, -hh + cr, math.pi),
               (hw - cr, -hh + cr, 3 * math.pi / 2))
    pts = []
    for cx, cz, a0 in corners:
        for i in range(n + 1):
            a = a0 + (math.pi / 2) * i / n
            pts.append((cx + cr * math.cos(a), cz + cr * math.sin(a)))
    return pts


def _wire(path):
    return dict(kind="wire", path=path, stock=WIRE_R)


def bow_round(r):
    """A plain ring."""
    return _wire(_polar(lambda t: r))


def bow_oval(r):
    """A ring drawn taller than it is wide."""
    return _wire(_sample(lambda t: (r * 0.84 * math.cos(t),
                                    r * 1.18 * math.sin(t))))


def bow_pear(r):
    """An egg, wide at the top and narrowing onto the shank."""
    return _wire(_recenter(_polar(lambda t: r * (1.0 + 0.24 * math.sin(t)))))


def bow_trefoil(r):
    """Three lobes, one straight up, with the shank leaving from a valley."""
    return _wire(_polar(lambda t: r * (1.0 + 0.24 * math.cos(3 * (t - math.pi / 2)))))


def bow_quatrefoil(r):
    """Four lobes on the compass points."""
    return _wire(_polar(lambda t: r * (1.0 + 0.18 * math.cos(4 * t))))


def bow_heart(r):
    """A heart, point down, so the shank runs out of the point."""
    def f(t):
        x = 16 * math.sin(t) ** 3
        z = (13 * math.cos(t) - 5 * math.cos(2 * t)
             - 2 * math.cos(3 * t) - math.cos(4 * t))
        return (x * r / 15.0, z * r / 15.0)
    return _wire(_recenter(_sample(f)))


def bow_plate(r):
    """A pierced rectangle, flat rather than round stock."""
    hw, hh, cr = r * 0.98, r * 1.16, r * 0.42
    return dict(kind="plate",
                outer=_rrect(hw, hh, cr),
                inner=_rrect(hw - PLATE_BAND, hh - PLATE_BAND, cr - PLATE_BAND * 0.5),
                thick=PLATE_THICK)


BOW_SHAPES = {
    "round": bow_round,
    "oval": bow_oval,
    "pear": bow_pear,
    "trefoil": bow_trefoil,
    "quatrefoil": bow_quatrefoil,
    "heart": bow_heart,
    "plate": bow_plate,
}


def _axis_crossings(loop):
    """Z values where a closed XZ loop crosses the vertical axis."""
    out = []
    n = len(loop)
    for i in range(n):
        x0, z0 = loop[i]
        x1, z1 = loop[(i + 1) % n]
        if (x0 <= 0.0 < x1) or (x1 <= 0.0 < x0):
            out.append(z0 + (z1 - z0) * (0.0 - x0) / (x1 - x0))
    return out


def bow_geometry(style, r):
    """
    Build a bow and measure the two points the rest of the key needs.

    hole_top is the top of the hole, where the ring wire rests. shank_z is where
    the shank leaves the bottom of the bow, set inside the metal so the two
    merge. line is the centerline of the bow's metal, and gauge is the thickest
    the metal gets, which is all the ring's opening size estimate needs.
    """
    shape = BOW_SHAPES[style](r)
    if shape["kind"] == "wire":
        crossings = _axis_crossings(shape["path"])
        return dict(shape,
                    hole_top=max(crossings) - shape["stock"],
                    shank_z=min(crossings) + shape["stock"] * 0.5,
                    line=shape["path"], gauge=shape["stock"])
    # A plate leans with the rest of the bow, and the lean carries its band
    # wider where the outline runs across the lean than where it runs with it.
    slant = math.tan(math.radians(BOW_TILT_DEG))
    mid, half = [], []
    for a, b in zip(shape["outer"], shape["inner"]):
        mid.append(((a[0] + b[0]) / 2, (a[1] + b[1]) / 2))
        dx, dz = (a[0] - b[0]) / 2, (a[1] - b[1]) / 2
        half.append(math.sqrt(dx * dx * (1.0 + slant * slant) + dz * dz))
    return dict(shape,
                hole_top=max(_axis_crossings(shape["inner"])),
                shank_z=min(_axis_crossings(shape["outer"])) + JOIN,
                line=mid,
                gauge=max(math.hypot(w, shape["thick"] / 2) for w in half))


# ──────────────────────────────────────────────────────────────────────────
# Shank
# ──────────────────────────────────────────────────────────────────────────

def shank_beads(style, length, bit_u, tip):
    """
    Turned rings down the shank, as (center, half-height, extra radius).

    Every style gets a collar under the bow, a neck just below it, and a
    shoulder above the bit. The rest is ornament. A negative extra radius cuts
    in rather than swells out. u is measured downward from the top of the shank.
    """
    beads = [(COLLAR_U, COLLAR_W, COLLAR_R - SHAFT_R),
             (COLLAR_U + COLLAR_W + 0.030, 0.036, -0.011)]
    if style in ("banded", "double"):
        beads.append((COLLAR_U + 0.10, 0.035, (COLLAR_R - SHAFT_R) * 0.45))
    if style == "double":
        beads.append((length * 0.52, 0.045, 0.016))
    beads.append((bit_u - 0.05, 0.045, 0.018))
    if tip == "bore":
        # A bored tip reads as a pipe only if its mouth swells. Seen head on,
        # the hole itself is invisible.
        beads.append((length - 0.05, 0.055, 0.016))
    return beads


def shank_profile(length, beads, tip, n=SHANK_SEG):
    """
    Radius samples from the top of the shank down to the tip.

    The shaft tapers over its length and each bead adds a raised-cosine bulge on
    top of it. A dome tip rounds off, a bore tip is drilled up the middle, and a
    flat tip is cut square.
    """
    def radius(u):
        t = u / length
        r = SHAFT_R * (1.0 - t * (1.0 - SHAFT_TAPER))
        for bu, half, extra in beads:
            d = abs(u - bu)
            if d < half:
                r += extra * 0.5 * (1.0 + math.cos(math.pi * d / half))
        return r

    dome = min(SHAFT_R, length * 0.05)
    pts = [(0.0, 0.0)]
    for i in range(n + 1):
        u = length * i / n
        r = radius(u)
        if tip == "dome" and u > length - dome:
            k = (u - (length - dome)) / dome
            r *= math.sqrt(max(0.0, 1.0 - k * k))
        pts.append((r, u))
    if tip == "bore":
        pts += [(BORE_R, length), (BORE_R, length - BORE_DEPTH), (0.0, length - BORE_DEPTH)]
    elif tip != "dome":
        pts.append((0.0, length))
    return pts


# ──────────────────────────────────────────────────────────────────────────
# Bit
# ──────────────────────────────────────────────────────────────────────────
# A pattern says how a bit is cut. cuts are notches in the outer edge, each
# (start, end, depth) — the first two as fractions along the bit, the third as a
# fraction of its reach. shoulder steps the top edge down near the shaft, as
# (width, drop). heel cuts the bottom outer corner back, as (height, depth).
# A heel has to start below the last cut. Overlap them and the outline crosses
# itself, which renders as a spike.

BIT_PATTERNS = {
    "comb2": dict(cuts=[(0.30, 0.52, 0.48), (0.66, 0.88, 0.48)], shoulder=(0.38, 0.16)),
    "comb3": dict(cuts=[(0.20, 0.36, 0.50), (0.46, 0.62, 0.50), (0.70, 0.86, 0.50)],
                  heel=(0.10, 0.34)),
    "fine": dict(cuts=[(0.18, 0.32, 0.58), (0.42, 0.56, 0.58), (0.66, 0.80, 0.58)]),
    "ward": dict(cuts=[(0.38, 0.60, 0.66)], shoulder=(0.42, 0.20)),
    "step": dict(cuts=[(0.52, 0.72, 0.52)], shoulder=(0.50, 0.24), heel=(0.16, 0.42)),
}


def bit_polygon(top, bot, width, side, pattern):
    """
    Outline of a warded bit in the key's local XZ plane.

    top and bot are distances below the bow. The plate hangs off the shaft on
    the given side, and the pattern cuts it.
    """
    span = bot - top
    out = width * side
    poly = []

    shoulder = pattern.get("shoulder")
    if shoulder:
        frac, drop = shoulder
        poly += [(0.0, -(top + span * drop)),
                 (out * frac, -(top + span * drop)),
                 (out * frac, -top)]
    else:
        poly.append((0.0, -top))
    poly.append((out, -top))

    # One notch per cut, taken from the outer edge. Wide lands between them keep
    # the plate solid; narrow lands turn to mush at icon size.
    for a, b, depth in pattern["cuts"]:
        inner = out * (1.0 - depth)
        poly += [(out, -(top + span * a)), (inner, -(top + span * a)),
                 (inner, -(top + span * b)), (out, -(top + span * b))]

    heel = pattern.get("heel")
    if heel:
        frac, depth = heel
        poly += [(out, -(bot - span * frac)),
                 (out * (1.0 - depth), -(bot - span * frac)),
                 (out * (1.0 - depth), -bot)]
    else:
        poly.append((out, -bot))

    poly.append((0.0, -bot))
    return poly


# ──────────────────────────────────────────────────────────────────────────
# Collision
# ──────────────────────────────────────────────────────────────────────────
# Every part is approximated by a chain of rods. A rod is a length of round
# stock: two ends and a radius. It holds the metal between its ends exactly,
# where a sphere on each sample holds only the samples and has to be widened to
# reach across the gap between them. That widening is what a settled bunch reads
# as, since keys drawn together come to rest against each other's models: fat
# spheres leave the metal apart, rods let it touch.
#
# Chains carry a bounding sphere and bodies carry one over all their chains, so
# nearly every pair is rejected without looking at a rod.

def _even(seq, n):
    """n items spread through seq, keeping the first and the last."""
    if len(seq) <= n:
        return list(seq)
    return [seq[round(i * (len(seq) - 1) / (n - 1))] for i in range(n)]


def rod(a, b, r):
    """
    A length of round stock: two ends, a radius, and the ball that holds it.

    Every test tries the ball first. Comparing two centers is a handful of
    arithmetic where measuring two segments is twenty times that, and almost
    every pair a settling fan asks about is nowhere near touching.
    """
    return (a, b, r, (a + b) / 2, (b - a).length / 2)


def gap_between(a0, a1, b0, b1):
    """Closest approach of two segments."""
    u, v, w = a1 - a0, b1 - b0, a0 - b0
    uu, vv, uv = u.dot(u), v.dot(v), u.dot(v)
    uw, vw = u.dot(w), v.dot(w)
    denom = uu * vv - uv * uv
    if uu <= 1e-12 and vv <= 1e-12:
        return w.length
    if uu <= 1e-12:
        s, t = 0.0, min(max(vw / vv, 0.0), 1.0)
    elif vv <= 1e-12:
        s, t = min(max(-uw / uu, 0.0), 1.0), 0.0
    else:
        s = min(max((uv * vw - uw * vv) / denom, 0.0), 1.0) if denom > 1e-12 else 0.0
        t = (uv * s + vw) / vv
        if t < 0.0:
            s, t = min(max(-uw / uu, 0.0), 1.0), 0.0
        elif t > 1.0:
            s, t = min(max((uv - uw) / uu, 0.0), 1.0), 1.0
    return (w + u * s - v * t).length


def rod_chain(samples, n, closed=True):
    """
    Cut a run of stock into n rods that hold all of it.

    samples are (point, radius) along the metal's centerline, as finely as it
    was drawn. A rod is a straight chord between two of them, and the run it
    stands in for bulges outside that chord wherever it curves or turns a
    corner. Each rod carries the deepest bulge along its own span, so a coarse
    chain over a tight lobe or a square corner stays fat enough to hold the
    metal instead of cutting across it. Where the run is already straight, which
    is most of a bit's outline and every side of a plate, the bulge is zero and
    the rod is exact.

    Cuts are placed by distance rather than by index, so however unevenly the
    outline was drawn, no one rod ends up standing in for most of it.
    """
    m = len(samples)
    span = m if closed else m - 1
    run = [0.0]
    for i in range(span):
        run.append(run[-1] + (samples[(i + 1) % m][0] - samples[i][0]).length)
    total = run[-1] or 1.0
    cuts, at = [], 0
    for i in range(n if closed else n - 1):
        want = total * i / (n if closed else n - 1)
        while at + 1 <= span and run[at + 1] <= want:
            at += 1
        if not cuts or at > cuts[-1]:
            cuts.append(at)
    if not closed and cuts[-1] != span:
        cuts.append(span)
    rods = []
    for k in range(len(cuts) if closed else len(cuts) - 1):
        i, j = cuts[k], cuts[(k + 1) % len(cuts)]
        a, b = samples[i % m][0], samples[j % m][0]
        axis = b - a
        long = axis.length_squared
        reach, step = 0.0, j if j > i else j + span
        for t in range(i, step + 1):
            point, r = samples[t % m]
            off = point - a
            if long > 1e-12:
                off = off - axis * min(max(off.dot(axis) / long, 0.0), 1.0)
            reach = max(reach, off.length + r)
        rods.append(rod(a, b, reach))
    return rods


def bow_rods(bow, lean, n=BOW_RODS):
    """
    The bow's metal as rods, in the frame the key is modeled in.

    The lean turns the bow's plane and carries the stock with it without
    changing its cross-section, so round stock needs one chain at the thickness
    it was drawn at. A plate is a flat band, too wide across for one rod to
    stand in for without sticking out past its faces, and the face is exactly
    what a neighboring bow comes to rest against. So a plate gets several chains
    laid down the width of its band, each only thick enough to hold its own
    slice of it.
    """
    if bow["kind"] == "wire":
        line = [(lean @ Vector((x, 0.0, z)), bow["stock"]) for x, z in bow["line"]]
        return rod_chain(line, n)

    edges = [(lean @ Vector((ox, 0.0, oz)), lean @ Vector((ix, 0.0, iz)))
             for (ox, oz), (ix, iz) in zip(bow["outer"], bow["inner"])]
    half = bow["thick"] / 2
    widest = max((out - inside).length for out, inside in edges)
    count = max(1, math.ceil(PLATE_RODS * widest / bow["thick"]))
    out = []
    for k in range(count):
        f = (k + 0.5) / count
        out += rod_chain([(inside + (edge - inside) * f,
                           math.hypot((edge - inside).length / (2 * count), half))
                          for edge, inside in edges], n)
    return out


def plate_fill(poly, half, lean):
    """
    The inside of a thin plate as rods, so nothing rests on its face unnoticed.

    An outline says where a plate's edges are and nothing about the metal
    between them, so a shank lying across the face of a bit reads as clear of
    it. Scanning the outline at intervals and laying a rod through each run of
    metal fills that in. The fill runs a hair fatter than the plate, because a
    rod on one scan line has to reach the next; the outline is traced at the
    plate's own thickness, so an edge still meets an edge exactly.
    """
    zs = [z for _, z in poly]
    low, high = min(zs), max(zs)
    lines = max(1, math.ceil((high - low) / half))
    step = (high - low) / lines
    thick = math.hypot(half, step / 2)
    out = []
    for i in range(lines + 1):
        z = min(max(low + step * i, low + 1e-4), high - 1e-4)
        xs = []
        for j in range(len(poly)):
            (x0, z0), (x1, z1) = poly[j - 1], poly[j]
            if (z0 > z) != (z1 > z):
                xs.append(x0 + (z - z0) * (x1 - x0) / (z1 - z0))
        xs.sort()
        for a, b in zip(xs[0::2], xs[1::2]):
            out.append(rod(lean @ Vector((a, 0.0, z)),
                           lean @ Vector((b, 0.0, z)), thick))
    return out


def chains(rods, kind, per=GROUP_SIZE):
    """Cut a run of rods into bounded groups."""
    out = []
    for i in range(0, len(rods), per):
        run = rods[i:i + per]
        center = sum((r[3] for r in run), Vector()) / len(run)
        out.append(dict(kind=kind, rods=run, center=center,
                        radius=max((r[3] - center).length + r[4] + r[2] for r in run)))
    return out


def body(groups):
    """Bundle groups into one body with a bound over all of them."""
    center = sum((g["center"] for g in groups), Vector()) / len(groups)
    return dict(groups=groups, center=center,
                radius=max((g["center"] - center).length + g["radius"]
                           for g in groups))


def moved(bod, matrix):
    """The same body somewhere else. A rigid move leaves every radius alone."""
    return dict(
        groups=[dict(kind=g["kind"], radius=g["radius"],
                     center=matrix @ g["center"],
                     rods=[(matrix @ a, matrix @ b, r, matrix @ mid, half)
                           for a, b, r, mid, half in g["rods"]])
                for g in bod["groups"]],
        center=matrix @ bod["center"], radius=bod["radius"])


def touching(a, b, skip=()):
    """True as soon as any rod of a overlaps one of b."""
    reach = a["radius"] + b["radius"]
    if (a["center"] - b["center"]).length_squared > reach * reach:
        return False
    return clearance(a, b, skip=skip, best=CONTACT_SLACK) < CONTACT_SLACK


def clearance(a, b, skip=(), best=1e9):
    """
    Smallest gap between two bodies. Negative is metal through metal.

    Nothing wider than best is measured; best comes back instead. Passing a
    cutoff is what keeps this cheap, since most of a body is nowhere near the
    closest point.
    """
    for ga in a["groups"]:
        if ga["kind"] in skip:
            continue
        for gb in b["groups"]:
            if gb["kind"] in skip:
                continue
            if ((ga["center"] - gb["center"]).length
                    - ga["radius"] - gb["radius"] > best):
                continue
            for a0, a1, ra, am, ah in ga["rods"]:
                for b0, b1, rb, bm, bh in gb["rods"]:
                    if (am - bm).length - ah - bh - ra - rb > best:
                        continue
                    gap = gap_between(a0, a1, b0, b1) - ra - rb
                    if gap < best:
                        best = gap
    return best


def key_body(bow, lean, profile, shank_z, poly):
    """
    The collision shape of one key, in the frame it is modeled in.

    A turned shank is a chain of rods down the axis, at the profile's own
    radius. A bit is a thin plate: its outline is traced at half the plate's
    thickness, and its face is filled in behind that.
    """
    return body(
        chains(bow_rods(bow, lean), "bow")
        + chains(rod_chain([(Vector((0.0, 0.0, shank_z - u)), max(r, 0.012))
                            for r, u in profile], SHANK_RODS, closed=False), "shank")
        + chains(rod_chain([(p, BIT_THICK / 2) for p in flat(poly, lean)], BIT_RODS)
                 + plate_fill(poly, BIT_THICK / 2, lean), "bit"))


def key_strands(bow, lean, profile, shank_z, poly):
    """
    The same key as runs of line, which is what the linking test needs.

    A rod chain says where the metal is. A strand says which way it goes,
    and threading is a question about direction.
    """
    loop = [lean @ Vector((x, 0.0, z)) for x, z in _even(bow["line"], BOW_RODS)]
    edge = flat(_even(poly, BIT_RODS), lean)
    return [loop + loop[:1],
            [Vector((0.0, 0.0, shank_z - u)) for _, u in _even(profile, SHANK_RODS)],
            edge + edge[:1]]


# ──────────────────────────────────────────────────────────────────────────
# The ring
# ──────────────────────────────────────────────────────────────────────────
# RING_RADIUS is a floor, not a fixed size: a bunch too big for it gets a
# bigger ring. Everything downstream reads the ring through RING, so the rest
# of the script never has to know which happened.

RING = {}


def set_ring(radius, stock=RING_WIRE_R):
    """Build the ring at a radius, along with the rods collision tests use."""
    seg = max(256, int(160 * radius))
    heft = stock / RING_WIRE_R
    path = [(radius * math.cos(2 * math.pi * i / seg),
             radius * math.sin(2 * math.pi * i / seg)) for i in range(seg)]
    points = [Vector((x, 0.0, z)) for x, z in path]
    wire = rod_chain([(p, stock) for p in points], seg)  # a rod per segment
    sleeve = rod_chain([(Vector((FERRULE_LEN * heft * (i / 4 - 0.5), 0.0, radius)),
                         FERRULE_R * heft) for i in range(5)], 4, closed=False)
    RING.update(radius=radius, stock=stock, path=path, points=points, wire=wire,
                body=body(chains(wire, "ring", per=16) + chains(sleeve, "ring")))


def bead_arc(gauge):
    """
    Arc of wire one bow claims.

    Two things set it, and the wider one wins. Every bow leans the same way, so
    their planes are parallel, and sliding a bow along the wire by s carries its
    plane sideways by s·tan(lean) — enough of that clears the next bow's stock.
    The collar under the bow is wider than that stock and hangs almost on the
    wire, where no amount of swinging separates it, so it claims its own width.

    This is only the opening estimate. It sizes the ring before anything is
    settled, so the bunch starts somewhere near where it will end up. What the
    keys actually need is measured, not predicted.
    """
    return max(2.0 * gauge * BEAD_MARGIN / math.tan(math.radians(BOW_TILT_DEG)),
               2.0 * COLLAR_R)


def size_ring(parts, span=FAN_MAX, floor=RING_RADIUS):
    """
    Grow the ring until everything on it has its arc of wire, and never shrink.

    The fan stops short of a full turn. A fan that closed on itself would put
    its two ends in the same place, and the wire has a joint at the top that
    whatever hangs on it should stay clear of anyway.
    """
    set_ring(max(floor, sum(p["arc"] for p in parts) / math.radians(span)))


set_ring(RING_RADIUS)


# ──────────────────────────────────────────────────────────────────────────
# Linking
# ──────────────────────────────────────────────────────────────────────────
# Two loops can be threaded through each other with room to spare, so touching
# never rules it out. Only the ring is allowed through a bow. Counting how often
# one key's metal crosses another key's hole is what rules out the rest.

def hole_frame(bow, lean):
    """A bow's hole as a flat polygon, with the frame it is measured in."""
    e1 = (lean @ Vector((1.0, 0.0, 0.0))).normalized()
    e2 = Vector((0.0, 0.0, 1.0))
    loop = [lean @ Vector((x, 0.0, z)) for x, z in bow["line"]]
    return dict(origin=Vector((0.0, 0.0, 0.0)), e1=e1, e2=e2,
                normal=e1.cross(e2).normalized(),
                poly=[(p.dot(e1), p.dot(e2)) for p in loop])


def hole_moved(hole, matrix):
    """The same hole somewhere else. Only the frame moves; the polygon is flat."""
    turn = matrix.to_3x3()
    return dict(origin=matrix @ hole["origin"], poly=hole["poly"],
                e1=turn @ hole["e1"], e2=turn @ hole["e2"],
                normal=turn @ hole["normal"])


def _inside(poly, u, v):
    """Point in polygon, by counting crossings of a ray along +u."""
    hit = False
    for i in range(len(poly)):
        (u0, v0), (u1, v1) = poly[i - 1], poly[i]
        if (v0 > v) != (v1 > v) and u < u0 + (v - v0) * (u1 - u0) / (v1 - v0):
            hit = not hit
    return hit


def pierces(hole, strand):
    """How many times a run of metal passes through a hole."""
    o, n = hole["origin"], hole["normal"]
    count = 0
    prev = (strand[0] - o).dot(n)
    for i in range(1, len(strand)):
        cur = (strand[i] - o).dot(n)
        if (prev > 0.0) != (cur > 0.0):
            at = strand[i - 1].lerp(strand[i], prev / (prev - cur)) - o
            if _inside(hole["poly"], at.dot(hole["e1"]), at.dot(hole["e2"])):
                count += 1
        prev = cur
    return count


def linked(a, b):
    """True if either key is threaded through the other."""
    return (any(pierces(a["hole"], s) % 2 for s in b["strands"])
            or any(pierces(b["hole"], s) % 2 for s in a["strands"]))


# ──────────────────────────────────────────────────────────────────────────
# Placement
# ──────────────────────────────────────────────────────────────────────────

def ring_point(hang_deg):
    """Where on the wire a bow is threaded."""
    a = math.radians(hang_deg)
    return Vector((RING["radius"] * math.cos(a), 0.0, RING["radius"] * math.sin(a)))


def swing_matrix(pivot, tilt_deg, flare_deg):
    """A key hung at pivot, leaned in the picture plane and out of it."""
    return (Matrix.Translation(pivot)
            @ Matrix.Rotation(-math.radians(tilt_deg), 4, 'Y')
            @ Matrix.Rotation(math.radians(flare_deg), 4, 'X'))


def hang_matrix(pivot, tilt_deg, flare_deg, drop):
    """The same, sunk by drop so the bow rests on the wire."""
    return (swing_matrix(pivot, tilt_deg, flare_deg)
            @ Matrix.Translation(Vector((0.0, 0.0, -drop))))


def rest_drop(rods, swing, pivot, ceiling, slack=CONTACT_SLACK):
    """
    How far a bow sinks before it rests on the ring wire.

    The bow starts centered on the wire and slides down. This returns the
    deepest it goes with its stock still clear of the ring's. It measures the
    same rods the collision test uses, so a resting bow reads as touching
    rather than as overlapping.

    The top of the hole is only the answer for a plain round bow. A lobed or
    square hole narrows above its widest point, so a bow hung from the very top
    of its hole cuts into the wire at the sides.

    Returns None when the bow cannot hang at all. A bow twisted far enough off
    the wire presents its hole edge-on, and past some angle no amount of sinking
    gets the wire through it.
    """
    # A bow rod can reach no further from the pivot than the deepest it sinks
    # plus its own extent, so most of the ring is out of the question before any
    # of it is measured.
    reach = ceiling + max(mid.length + half + r for _, _, r, mid, half in rods)
    near = [w for w in RING["wire"]
            if (w[3] - pivot).length - w[4] - w[2] < reach + slack]

    def rests(drop):
        hung = swing @ Matrix.Translation(Vector((0.0, 0.0, -drop)))
        for a, b, r, mid, half in rods:
            pa, pb, pm = hung @ a, hung @ b, hung @ mid
            for q0, q1, rq, qm, qh in near:
                room = r + rq + slack
                if (pm - qm).length - half - qh > room:
                    continue
                if gap_between(pa, pb, q0, q1) < room:
                    return False
        return True

    if rests(ceiling):
        return ceiling
    if not rests(0.0):
        return None
    lo, hi = 0.0, ceiling
    for _ in range(18):
        mid = (lo + hi) / 2
        if rests(mid):
            lo = mid
        else:
            hi = mid
    return lo


def drop_table(part, flare):
    """
    How far a bow sinks onto the wire, measured across the twists it can take.

    Twist is the angle between a bow's plane and the wire running through it. It
    is what decides how the bow sits, so the measurement is made once here and
    read back during settling rather than repeated for every pose.

    The table stops where the bow stops fitting. Twist a loop far enough and it
    meets the wire edge-on, and no amount of sinking gets the wire through the
    hole. Where that happens depends on the shape of the hole, so every key ends
    up with its own limit.

    Both directions are measured. A bow's plane already leans one way, so
    twisting it with that lean and against it are not the same move and do not
    reach the same limit.
    """
    pivot = ring_point(-90.0)
    steps = int(TWIST_MAX / DROP_STEP)
    # The table is read between its samples, so each entry holds a little more
    # daylight than a resting bow needs, to cover the rotation in between.
    slack = CONTACT_SLACK + math.radians(DROP_STEP) * BOW_BASE * 0.5
    drops = {0: rest_drop(part["bow_rods"], swing_matrix(pivot, 0.0, flare),
                          pivot, part["hole_top"], slack) or 0.0}
    limit = {}
    for sign in (1, -1):
        reach = 0
        for i in range(1, steps + 1):
            drop = rest_drop(part["bow_rods"],
                             swing_matrix(pivot, sign * i * DROP_STEP, flare),
                             pivot, part["hole_top"], slack)
            if drop is None:
                break
            drops[sign * i] = drop
            reach = i
        limit[sign] = reach * DROP_STEP
    return dict(drops=drops, limit=limit)


def drop_at(part, twist):
    """
    Read the drop table between its samples.

    The table bends the way a hole narrows, so a straight line between two
    samples runs under the real curve and the bow hangs a hair high rather than
    a hair low. That is the safe side of the wire.
    """
    table = part["drops"]["drops"]
    step = twist / DROP_STEP
    low = math.floor(step)
    if low not in table:
        return table[min(table)] if step < 0 else table[max(table)]
    if low + 1 not in table:
        return table[low]
    return table[low] + (table[low + 1] - table[low]) * (step - low)


def key_lean(spec, part, hang_deg):
    """
    How a key leans, as the wire's own direction plus a twist off it.

    A bow has to stay roughly square to the wire it hangs on, so the lean is
    built from the tangent rather than from vertical, and the key's designed
    tilt is the twist away from that. The twist is allowed only as far as the
    hole admits the wire: a bow twisted far enough presents its hole edge-on and
    the wire no longer goes through. A key that runs out of twist goes radial
    instead, which is how a loaded ring looks.
    """
    radial = hang_deg + 90.0
    limit = part["drops"]["limit"]
    twist = max(-limit[-1], min(limit[1], spec["tilt_deg"] - radial))
    return radial + twist, twist


def key_pose(spec, part, hang_deg):
    """
    Where a key sits with its bead at hang_deg, and the shapes that test it.

    The bead slides but the key keeps the lean it was designed with, so closing
    a bunch up crowds the bows together without flattening the fan of shafts
    below them. That is the shape a loaded ring takes: the bows have nowhere to
    go, and everything below the ring still splays.
    """
    pivot = ring_point(hang_deg)
    tilt, twist = key_lean(spec, part, hang_deg)
    matrix = hang_matrix(pivot, tilt, spec["flare_deg"], drop_at(part, twist))
    return dict(matrix=matrix, body=moved(part["body"], matrix),
                hole=hole_moved(part["hole"], matrix),
                strands=[[matrix @ p for p in s] for s in part["strands"]])


def relax(specs, parts, hangs, pull, draw=0.0):
    """
    Let the bunch settle, and report the deepest overlap left.

    Two keys sharing space are pushed apart along the wire. The push widens the
    whole run of gaps between the pair rather than moving the two keys alone: a
    bead in the middle of a packed row has nowhere to go by itself, so the row
    has to open around it.

    Three things then decide where a key comes to rest. pull drifts every gap
    back toward the one the fan was designed with. draw does the opposite for
    the gap beside a key: a key with daylight next to it slides toward its
    neighbor until their metal meets, which is how a bunch on a real ring hangs
    and what keeps a designed span from reading as five keys held apart. Use one
    or the other, not both, or they settle at a balance between them rather than
    at either.

    Returns the deepest overlap and how much more wire the fan asked for than
    the ring has. The second number is how much bigger the ring needs to be.
    """
    count = len(hangs)
    want = [specs[i + 1]["hang_deg"] - specs[i]["hang_deg"] for i in range(count - 1)]
    worst, crowd = 0.0, 1.0
    for _ in range(SETTLE_PASSES):
        poses = [key_pose(s, p, h) for s, p, h in zip(specs, parts, hangs)]
        widen = [0.0] * (count - 1)
        worst, loose = 0.0, 0.0
        for i in range(count):
            for j in range(i + 1, count):
                a, b = poses[i]["body"], poses[j]["body"]
                # Only a key and the one beside it are drawn together, and only
                # they need their daylight measured. Every other pair is asked
                # nothing but whether it overlaps, which is far cheaper.
                side = draw > 0.0 and j == i + 1
                reach = DRAW_REACH if side else CONTACT_SLACK
                if ((a["center"] - b["center"]).length
                        - a["radius"] - b["radius"] > reach):
                    gap = reach
                else:
                    gap = clearance(a, b, best=reach)
                    if linked(poses[i], poses[j]):
                        gap = min(gap, -LINK_PUSH)
                if gap < CONTACT_SLACK:
                    deep = CONTACT_SLACK - gap
                    worst = max(worst, deep)
                    share = math.degrees(deep * SETTLE_PUSH / RING["radius"]) / (j - i)
                    for k in range(i, j):
                        widen[k] += share
                elif side:
                    free = gap - CONTACT_SLACK
                    loose = max(loose, free)
                    widen[i] -= math.degrees(free * draw / RING["radius"])
        if worst == 0.0 and loose == 0.0 and pull == 0.0:
            break
        gaps = [max(0.0, (hangs[i + 1] - hangs[i]) + widen[i]
                    + (want[i] - (hangs[i + 1] - hangs[i])) * pull)
                for i in range(count - 1)]
        span = sum(gaps)
        if span > FAN_MAX:
            crowd = max(crowd, span / FAN_MAX)
            gaps = [g * FAN_MAX / span for g in gaps]
        run = [0.0]
        for gap in gaps:
            run.append(run[-1] + gap)
        # Slide the whole run back under the middle of the fan.
        middle = (sum(s["hang_deg"] for s in specs) - sum(run)) / count
        hangs[:] = [r + middle for r in run]
    return worst, crowd


def settle(specs, parts, what="keys", floor=RING_RADIUS):
    """
    Hang the bunch: settle it, and grow the ring only if it will not fit.

    The first run holds the fan near the span it was designed with while the
    overlaps come out. The second lets go of that and closes the bunch up, so
    the span the keys end on is the one their own metal leaves them.

    A fan that still overlaps once it has spread the whole way around has run
    out of wire. Every key is then jammed against the end of the fan, and the
    only answer is a bigger ring, which is the answer a real bunch needs too.
    """
    hangs = [s["hang_deg"] for s in specs]
    for _ in range(GROW_TRIES):
        for spec, part in zip(specs, parts):
            part["drops"] = drop_table(part, spec["flare_deg"])
        relax(specs, parts, hangs, SETTLE_PULL)
        worst, crowd = relax(specs, parts, hangs, 0.0, SETTLE_DRAW)
        # Settled means no metal through metal. Keys drawn together come to rest
        # within a whisker of CONTACT_SLACK and rarely land exactly on it, so
        # asking for the full slack back would keep the bunch settling forever.
        if worst < CONTACT_SLACK:
            break
        if crowd <= 1.0:
            continue
        set_ring(RING["radius"] * min(max(crowd, GROW_LEAST), GROW_MOST),
                 RING["stock"])

    for spec, part, hang in zip(specs, parts, hangs):
        pose = key_pose(spec, part, hang)
        for obj, local in part["group"]:
            obj.matrix_world = pose["matrix"] @ local
        part["placed"] = pose
    grown = "" if RING["radius"] <= floor + 1e-9 else \
        f", grown from {floor:.2f} to hold them"
    print(f"  {len(specs)} {what} over {max(hangs) - min(hangs):.0f} degrees "
          f"of a radius {RING['radius']:.2f} ring{grown}")


def report_clearance(parts):
    """
    Print how close each key comes to the ring and to its nearest neighbor.

    A bow resting on the wire reads a hair positive against the ring, which is
    the daylight the solver leaves. Anything negative means metal passes through
    metal, and the build says so.
    """
    rows = []
    for i, part in enumerate(parts):
        here = part["placed"]["body"]
        beside = 1e9
        for j, other in enumerate(parts):
            if j == i:
                continue
            there = other["placed"]["body"]
            if ((here["center"] - there["center"]).length
                    - here["radius"] - there["radius"] > beside):
                continue
            beside = clearance(here, there, best=beside)
        rows.append((part["name"],
                     clearance(here, RING["body"], skip=("shank", "bit")),
                     clearance(here, RING["body"], skip=("bow",)),
                     beside))

    worst = min(min(r[1:]) for r in rows)
    show = rows
    if len(rows) > 12:
        show = sorted(rows, key=lambda r: min(r[1:]))[:5]
        print(f"  the five tightest of {len(rows)}:")
    for name, ring, shaft, beside in show:
        near = "     —" if beside > 100 else f"{beside:+.3f}"
        print(f"  {name}  ring {ring:+.3f}  shaft {shaft:+.3f}  beside {near}")
    if worst < 0:
        print(f"  CLIPPING by {-worst:.3f}. Raise SETTLE_PASSES, or FAN_MAX "
              f"so the bunch has more wire to spread along.")


# ──────────────────────────────────────────────────────────────────────────
# Assembly
# ──────────────────────────────────────────────────────────────────────────

def build_key(spec):
    """
    Build one key as a single mesh object, hanging from the origin.

    Where it ends up is `settle`'s job. This returns the object and everything
    the solver needs: the bow's centerline, its stock, the top of its hole, and
    the key's collision shape.
    """
    bow = bow_geometry(spec["bow"], spec["bow_r"])
    length = spec["length"]

    bm = bmesh.new()

    # Lean the key's plane out of the ring's plane, or the bow's stock and the
    # ring's occupy the same space and cut through each other at both crossings.
    # The lean is a shear rather than a rotation: the plane tilts by
    # BOW_TILT_DEG while every point keeps its height and its distance across
    # the picture, so every outline is unchanged head on. A rotation would
    # foreshorten the bow and the bit both. Only the outlines are sheared. Metal
    # is laid on afterwards, square to the leaned plane, so stock and plate keep
    # the thickness they were drawn at instead of stretching with the shear.
    # A key hung straight on the ring is sheared, which keeps its outline true
    # head on. A key hung on a small ring that is itself turned out of the
    # picture is turned instead, by the same angle the other way, so the two
    # cancel and the key comes back square to the camera with nothing stretched.
    angle = math.radians(BOW_TILT_DEG) * spec["tilt_side"]
    if spec.get("turn"):
        lean = Matrix.Rotation(angle, 4, 'Z')
        face = Vector((-math.sin(angle), math.cos(angle), 0.0))
    else:
        slant = math.tan(angle)
        lean = Matrix(((1.0, 0.0, 0.0, 0.0),
                       (slant, 1.0, 0.0, 0.0),
                       (0.0, 0.0, 1.0, 0.0),
                       (0.0, 0.0, 0.0, 1.0)))
        face = Vector((-slant, 1.0, 0.0)).normalized()

    # The bit goes in the same plane, by the same shear. A real key is one flat
    # thing: its bow and its bit line up, and looking down the shank shows one
    # band, not two crossing at an angle. The shank is turned round its axis, so
    # the lean does not touch it.

    if bow["kind"] == "wire":
        sweep(bm, flat(bow["path"], lean), bow["stock"], face)
    else:
        band(bm, flat(bow["outer"], lean), flat(bow["inner"], lean),
             bow["thick"], face)

    # The shank hangs off the bottom of the bow. Distances below the bow center
    # are positive; z in the same frame is negative.
    shank_z = bow["shank_z"]
    bit_bot = length - TIP_LEN * spec["stub"]
    bit_top = bit_bot - BIT_LEN
    shank_len = length + shank_z
    beads = shank_beads(spec["shank"], shank_len, bit_top + shank_z, spec["tip"])
    profile = shank_profile(shank_len, beads, spec["tip"])
    lathe(bm, profile, shank_z)

    poly = bit_polygon(bit_top, bit_bot, BIT_W * spec["bit_w"],
                       spec["bit_side"], BIT_PATTERNS[spec["bit"]])
    grown = len(bm.faces)
    prism(bm, flat(poly, lean), BIT_THICK, face)

    # Chamfer the bit. A square-edged plate renders as one flat tone and reads
    # as paper; the chamfer gives it a highlight along every edge.
    bm.faces.ensure_lookup_table()
    plate = list(bm.faces)[grown:]
    bmesh.ops.bevel(bm, geom=list({e for f in plate for e in f.edges}),
                    offset=BIT_BEVEL, segments=1, affect='EDGES',
                    clamp_overlap=True)

    bmesh.ops.recalc_face_normals(bm, faces=bm.faces[:])
    bm.normal_update()
    mesh = bpy.data.meshes.new(spec["name"])
    bm.to_mesh(mesh)
    bm.free()

    obj = bpy.data.objects.new(spec["name"], mesh)
    shape = key_body(bow, lean, profile, shank_z, poly)
    return obj, dict(
        name=spec["name"],
        group=[(obj, Matrix())],
        arc=bead_arc(bow["gauge"]),
        hole_top=bow["hole_top"],
        body=shape,
        drops=[],
        hole=hole_frame(bow, lean),
        strands=key_strands(bow, lean, profile, shank_z, poly),
        bow_rods=[rod for g in shape["groups"] if g["kind"] == "bow"
                  for rod in g["rods"]])


def ferrule_profile(length, r, n=24):
    """A barrel with rounded ends: the sleeve closing the ring's joint."""
    pts = []
    for i in range(n + 1):
        u = length * i / n
        pts.append((r * math.sqrt(max(0.0, 1.0 - (2 * u / length - 1) ** 8)), u))
    return pts


def build_ring():
    bm = bmesh.new()
    heft = RING["stock"] / RING_WIRE_R
    sweep(bm, flat(RING["path"]), RING["stock"])

    # The ring is one loop of stock, so its ends meet somewhere. The sleeve sits
    # at the top, lying along the ring's tangent there.
    sleeve = (Matrix.Translation(Vector((0.0, 0.0, RING["radius"])))
              @ Matrix.Rotation(math.radians(90), 4, 'Y'))
    lathe(bm, ferrule_profile(FERRULE_LEN * heft, FERRULE_R * heft),
          FERRULE_LEN * heft / 2, matrix=sleeve)
    bmesh.ops.recalc_face_normals(bm, faces=bm.faces[:])
    bm.normal_update()
    mesh = bpy.data.meshes.new("Ring")
    bm.to_mesh(mesh)
    bm.free()
    return bpy.data.objects.new("Ring", mesh)


# ──────────────────────────────────────────────────────────────────────────
# Scene
# ──────────────────────────────────────────────────────────────────────────

def clear_scene():
    for coll in (bpy.data.objects, bpy.data.meshes,
                 bpy.data.materials, bpy.data.lights, bpy.data.cameras):
        for item in list(coll):
            coll.remove(item, do_unlink=True)


def brass_material(name, tint, roughness):
    mat = bpy.data.materials.new(name)
    mat.use_nodes = True
    bsdf = mat.node_tree.nodes["Principled BSDF"]
    bsdf.inputs["Base Color"].default_value = (BRASS[0] * tint, BRASS[1] * tint,
                                               BRASS[2] * tint, 1.0)
    bsdf.inputs["Metallic"].default_value = 1.0
    bsdf.inputs["Roughness"].default_value = roughness
    return mat


def shade_smooth(obj):
    """Smooth the round stock but keep the bit's edges crisp."""
    for poly in obj.data.polygons:
        poly.use_smooth = True
    mod = obj.modifiers.new("Sharpen", 'EDGE_SPLIT')
    mod.split_angle = math.radians(40)


def build(keys=None):
    keys = KEYS if keys is None else keys
    clear_scene()
    coll = bpy.data.collections.new("KeyRing")
    bpy.context.scene.collection.children.link(coll)

    built = [build_key(k) for k in keys]
    parts = [part for _, part in built]
    size_ring(parts)
    settle(keys, parts)
    objects = [build_ring()] + [obj for obj, _ in built]
    dress(objects, coll)
    report_clearance(parts)
    return objects


def dress(objects, coll):
    """Give every object its patina and put it in the scene."""
    brass = [brass_material(f"Brass{i + 1}", tint, rough)
             for i, (tint, rough) in enumerate(PATINA)]
    for i, obj in enumerate(objects):
        obj.data.materials.append(brass[i % len(brass)])
        shade_smooth(obj)
        coll.objects.link(obj)


# ──────────────────────────────────────────────────────────────────────────
# Bunches of bunches
# ──────────────────────────────────────────────────────────────────────────

def make_rings(count=NEST_COUNT):
    """Fan `count` small rings across the bottom of the central one."""
    rings = []
    for i in range(count):
        c = (i / (count - 1) - 0.5) if count > 1 else 0.0
        hang = -90.0 + NEST_SPAN * c
        rings.append(dict(name=f"Bunch{i + 1}",
                          hang_deg=hang,
                          tilt_deg=(hang + 90.0) * NEST_TILT_GAIN,
                          flare_deg=NEST_FLARE * c))
    return rings


def build_bunch(keys, tag):
    """Build a small ring, settle its keys on it, and hand back the lot."""
    set_ring(RING_RADIUS)
    built = [build_key(k) for k in keys]
    parts = [part for _, part in built]
    size_ring(parts)
    settle(keys, parts, what=f"keys on {tag}")
    obj = build_ring()
    obj.name = obj.data.name = f"{tag}Ring"
    return obj, built, parts, dict(RING)


def pendant(spec, ring_obj, built, parts, small, turn):
    """
    One settled bunch, as something the solver can hang on a bigger ring.

    Every field a key hands the solver, a bunch hands it too: the loop that
    threads on the wire, how deep the wire sits in it, the metal to keep clear
    of, and the hole nothing else may pass through. The small ring stands in for
    the bow and the keys come along for the ride.

    A bunch is tested as one thing, so its metal is regrouped into fewer, larger
    bounding groups than a key's, and the loop and strands the threading test
    reads are thinned. Both keep a question that is asked of every pair on every
    pass from costing what a bunch's worth of rods would cost.
    """
    roll = Matrix.Rotation(-math.radians(BOW_TILT_DEG) * turn, 4, 'Z')

    rods = {}
    for part in parts:
        for group in part["placed"]["body"]["groups"]:
            rods.setdefault(group["kind"], []).extend(group["rods"])
    for group in small["body"]["groups"]:
        rods.setdefault(group["kind"], []).extend(group["rods"])
    shape = body([chain for kind, run in rods.items()
                  for chain in chains(run, kind, per=NEST_GROUP)])

    strands = [_even(s, NEST_STRAND) for part in parts
               for s in part["placed"]["strands"]]
    strands.append([Vector((x, 0.0, z)) for x, z in small["path"][::NEST_POLY]])

    return dict(
        name=spec["name"],
        group=([(ring_obj, roll)]
               + [(obj, roll @ part["placed"]["matrix"])
                  for (obj, _), part in zip(built, parts)]),
        arc=2.0 * small["radius"],
        hole_top=small["radius"] - small["stock"],
        body=moved(shape, roll),
        bow_rods=[rod(roll @ a, roll @ b, r) for a, b, r, _, _ in rods["ring"]],
        hole=hole_frame(dict(line=small["path"][::NEST_POLY]), roll),
        strands=[[roll @ p for p in s] for s in strands],
        drops=[])


def build_nest(count=NEST_COUNT, keys=NEST_KEYS):
    """A central ring with `count` settled bunches hanging on it."""
    clear_scene()
    coll = bpy.data.collections.new("KeyRing")
    bpy.context.scene.collection.children.link(coll)

    specs = make_rings(count)
    hung = []
    for i, spec in enumerate(specs):
        tag = spec["name"]
        ring_obj, built, parts, small = build_bunch(
            make_keys(keys, phase=i * 2, tag=f"{tag}-", turn=True), tag)
        hung.append(pendant(spec, ring_obj, built, parts, small, BOW_TILT_SIDE))

    # The central ring is set from the bunches it carries rather than from the
    # arc they claim: they nest into each other like bows do, so what they claim
    # says little about how big a ring reads right under them.
    floor = NEST_SCALE * max(part["arc"] for part in hung) / 2.0
    set_ring(floor, NEST_WIRE_R)
    settle(specs, hung, what="bunches", floor=floor)

    objects = [build_ring()] + [obj for part in hung for obj, _ in part["group"]]
    dress(objects, coll)
    report_clearance(hung)
    return objects


def bounds(objects):
    """World-space bounding box of the built model."""
    pts = [obj.matrix_world @ Vector(c)
           for obj in objects for c in obj.bound_box]
    lo = Vector((min(p.x for p in pts), min(p.y for p in pts), min(p.z for p in pts)))
    hi = Vector((max(p.x for p in pts), max(p.y for p in pts), max(p.z for p in pts)))
    return lo, hi


def setup_render(objects, size, samples=128, padding=1.10):
    """Frame the model square and front on, lit for metal, over transparency."""
    scene = bpy.context.scene
    lo, hi = bounds(objects)
    center = (lo + hi) / 2
    extent = max(hi.x - lo.x, hi.z - lo.z) * padding

    cam_data = bpy.data.cameras.new("Camera")
    cam_data.type = 'ORTHO'
    cam_data.ortho_scale = extent
    cam = bpy.data.objects.new("Camera", cam_data)
    cam.location = (center.x, lo.y - 6.0, center.z)
    cam.rotation_euler = (math.radians(90), 0, 0)   # look toward +Y
    scene.collection.objects.link(cam)
    scene.camera = cam

    def area(name, loc, energy, sizing, target=center):
        data = bpy.data.lights.new(name, 'AREA')
        data.energy = energy
        data.size = sizing
        light = bpy.data.objects.new(name, data)
        light.location = loc
        direction = (Vector(target) - Vector(loc)).normalized()
        light.rotation_euler = direction.to_track_quat('-Z', 'Y').to_euler()
        scene.collection.objects.link(light)

    area("Key",  (-4, -6, 5), 900, 8)
    area("Fill", (5, -5, 0), 350, 8)
    area("Rim",  (2, 5, 4), 600, 8)

    # Metal needs something to reflect, and the world is what it gets.
    world = bpy.data.worlds.new("World")
    world.use_nodes = True
    world.node_tree.nodes["Background"].inputs[0].default_value = (0.35, 0.35, 0.38, 1)
    scene.world = world

    scene.render.engine = 'CYCLES'
    scene.cycles.samples = samples
    scene.render.film_transparent = True
    scene.render.resolution_x = size
    scene.render.resolution_y = size
    scene.render.image_settings.file_format = 'PNG'
    scene.render.image_settings.color_mode = 'RGBA'


def main():
    argv = sys.argv[sys.argv.index("--") + 1:] if "--" in sys.argv else []
    here = os.path.dirname(os.path.abspath(__file__)) if "__file__" in globals() else os.getcwd()

    def opt(flag, default):
        return type(default)(argv[argv.index(flag) + 1]) if flag in argv else default

    size = opt("--size", 1024)
    samples = opt("--samples", 128)
    count = opt("--keys", 0)
    nest = opt("--nest", 0)

    if nest:
        objects = build_nest(nest, count or NEST_KEYS)
        print(f"built a ring of {nest} rings of {count or NEST_KEYS} keys")
    else:
        keys = make_keys(count) if count else KEYS
        objects = build(keys)
        print(f"built ring + {len(keys)} keys")

    if "--render" in argv or "--save" in argv:
        setup_render(objects, size=size, samples=samples)

    if "--save" in argv:
        bpy.ops.wm.save_as_mainfile(filepath=os.path.join(here, "key_ring.blend"))

    if "--render" in argv:
        out_dir = os.path.join(here, "renders")
        os.makedirs(out_dir, exist_ok=True)
        master = os.path.join(out_dir, f"icon-{size}.png")
        bpy.context.scene.render.filepath = master
        bpy.ops.render.render(write_still=True)
        print(f"wrote {master}")

        if "--sizes" in argv:
            write_icon_set(master, out_dir)


def write_icon_set(master, out_dir):
    """Downsample the master render into the size set packaging consumes."""
    for px in ICON_SIZES:
        img = bpy.data.images.load(master)
        img.scale(px, px)
        img.filepath_raw = os.path.join(out_dir, f"{px}.png")
        img.file_format = 'PNG'
        img.save()
        bpy.data.images.remove(img)
    print(f"wrote {len(ICON_SIZES)} icons: {', '.join(str(s) for s in ICON_SIZES)}")


main()

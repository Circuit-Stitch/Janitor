# Icon source

A Blender model of a key ring, built for the Janitor app icon. `key_ring.py`
generates the model and renders it.

## Provenance and usage rights

The first version of this model took its arrangement from a reference drawing of
a key ring. That drawing is not licensed for redistribution, so it is not in this
repository. Neither are the photographs of antique keys used later.

Nothing is traced from either. `make_keys` generates the fan from `KEY_COUNT`,
`HANG_SPAN`, and the constants beside them. Every bow, bit, and shank is a
parametric curve built from period key forms that are centuries old — a trefoil,
a heart, a pierced plate, a warded bit. No outline is sampled from an image.

`BRASS` was once sampled from the drawing's midtone. It is now a chosen value,
so no color traces back either.

Some proportions still do. Shaft radius and the bit dimensions began as
measurements off the drawing. They describe how a real skeleton key is
proportioned rather than how the drawing arranged one. Change those constants if
you want the model clear of it entirely. Bow stock and bow radius also started
there, and no longer match: `WIRE_R` and `BOW_BASE` are chosen values now.

`key_ring.blend` and anything under `renders/` are built output. Both bake in
whatever the constants said at the time. Rebuild them after changing a constant
so no stale geometry survives.

## Running it

```sh
blender -b -P key_ring.py -- --render --sizes --save
```

| Flag | Effect |
| --- | --- |
| `--render` | Writes `renders/icon-1024.png` with a transparent background. |
| `--sizes` | Downsamples that master into 16, 24, 32, 48, 64, 128, 256, and 512. |
| `--save` | Writes `key_ring.blend`. |
| `--size N` | Master render resolution. Defaults to 1024. |
| `--samples N` | Cycles samples. Defaults to 128. Drop to 32 while iterating. |
| `--keys N` | Build N keys instead of `KEY_COUNT`, without editing the file. |
| `--nest N` | Build a central ring carrying N of these bunches, instead of one bunch on its own. `--keys` then sets the keys on each. |

All three flags together take about six seconds for the five keys the icon
ships. Settling a bunch is the slow part and it grows with the count: twelve keys
take about three seconds, twenty about thirty, fifty about eighty-five. The jump
is the ring growing: a fan that fits its first ring settles once, and one that
does not settles again at every size it tries.

Every build settles the bunch and prints its clearance check before rendering,
so `blender -b -P key_ring.py -- --keys 20` on its own is a fast way to see
whether a change made the metal intersect.

You can also open `key_ring.blend` directly, or paste `key_ring.py` into the
Blender Text Editor and press Run Script. Running the script from the editor
builds the model and skips the render.

## How a key is put together

Four parts, built as one mesh per key.

| Part | Built from |
| --- | --- |
| Bow | A closed outline. Round stock sweeps along it, or flat metal fills between an outer and an inner outline. |
| Shank | A radius-versus-depth profile revolved around the axis. Collars, necks, and shoulders are bumps in that profile. |
| Bit | A cut outline extruded sideways, then chamfered so its edges catch light. |
| Tip | The last section of the shank profile. It domes over, bores out, or cuts off square. |

## How the bunch hangs

Nothing here is placed by hand. `settle` works out where every key ends up, and
no two pieces of metal are allowed to share space or thread through each other.

**The ring passes through the bow, not through its metal.** A bow drawn flat in
the picture plane is coplanar with the ring, so the two loops cross twice and the
stock cuts through itself at both crossings. Every key therefore leans out of the
ring's plane by `BOW_TILT_DEG`. The lean is a shear, not a rotation. Every point
keeps its height and its distance across the picture, so every outline is
unchanged head on. A rotation would foreshorten the bow and the bit both.

**The bow and the bit share one plane.** A real key is one flat thing: looking
down the shank shows a single band, not two crossing at an angle. So the same
shear carries the bit. The shank is turned round its axis, so the lean does not
touch it.

**Only the outlines are sheared.** Metal is laid on afterwards, square to the
leaned plane, so stock and plate keep the thickness they were drawn at. Shearing
the solid instead stretches round stock into an ellipse and a plate into a
parallelogram, both widest where the outline runs vertically — which is exactly
where the ring's wire crosses the bow.

**Every bow leans the same way.** Alternating them looks like it would separate
neighbors and does the opposite — the right edge of one bow and the left edge of
the next land at the same depth and cut through each other. Leaning them all one
way pulls those two edges apart, and it keeps the bow planes parallel. Two loops
whose planes are not parallel always cross somewhere.

**A key's lean is built from the wire, not from vertical.** A bow has to stay
roughly square to the wire it hangs on, or its hole no longer admits the wire at
all. So the lean starts at the ring's own tangent, and the key's designed
`tilt_deg` is a twist away from that. `drop_table` measures how far each hole can
be twisted before the wire stops fitting, in both directions, and the twist is
clamped there. A key gets the lean it asks for wherever the hole allows it. One
pushed far around the ring runs out of twist and goes radial, which is how a
loaded ring looks.

The lean stays with the key, not with the bead. Sliding a bead along the wire
therefore crowds the bows together without flattening the fan of shafts below
them.

**A key sinks until it rests.** `rest_drop` searches for the deepest the bow can
hang without its stock cutting into the ring's. The top of the hole is the answer
only for a plain round bow; a lobed or square hole narrows above its widest point,
so a bow hung from the very top cuts into the wire at the sides.

**Crowded keys make room along the wire.** `relax` runs the bunch as beads on a
string. Any two keys sharing space push apart. The push widens the whole run of
gaps between the pair, not just the two keys — a bead in the middle of a packed
row has nowhere to go by itself, so the row opens around it.

**Loose keys close the gap.** A key with daylight beside it slides toward its
neighbor until their metal meets, at `SETTLE_DRAW` of the remaining daylight per
pass. That is what makes a bunch hang like a bunch instead of like five keys held
apart at even spacing. `HANG_SPAN` lays the fan out and sets how much it splays;
the span the keys settle on is whatever their own metal leaves them. Set
`SETTLE_DRAW` to zero to have the fan stay at its designed spacing and move only
where keys overlap.

**The collision model is rods, not spheres.** A rod is a length of round stock:
two ends and a radius. It holds the metal between its ends exactly. A sphere on
each sample holds only the samples, and has to be widened to reach across the gap
between them — and that widening is what a settled bunch reads as, because keys
drawn together come to rest against each other's models. Rods let the metal
touch; spheres leave it a few hundredths apart.

Each rod also carries the deepest bulge along its own span, so a chain that
crosses a tight lobe or a square corner stays fat enough to hold the metal
instead of cutting across it. Set `BOW_RODS` and friends at or above the counts
the mesh itself is built from and the model stops approximating altogether: a rod
per drawn segment is the drawn segment.

A bit is a thin plate. Its outline is traced at half the plate's thickness, and
`plate_fill` scans the outline at intervals and lays a rod through each run of
metal, so a shank lying across a bit's face does not read as clear of it.

**Keys never link.** Two loops can thread through each other with room to spare,
so a collision test alone never rules it out. Only the ring is allowed through a
bow. `pierces` counts how often one key's metal crosses another key's hole, and an
odd count means they are threaded together, which settling treats as a deep
overlap and drives apart.

**The ring grows rather than overfilling.** `RING_RADIUS` is a floor. When a fan
has spread as far around the ring as `FAN_MAX` allows and keys still overlap, the
bunch is out of wire, and the ring grows by the shortfall and settles again. A
real bunch that size needs a bigger ring too.

`report_clearance` prints the result on every build.

```
  Key01  ring +0.010  shaft +0.327  beside +0.002
  Key02  ring +0.010  shaft +0.290  beside +0.002
```

`ring` is the bow against the wire, `shaft` is everything below the bow against
the wire, and `beside` is the whole key against its nearest neighbor. A bow at
rest reads a hair positive, and so does a key drawn up against the one beside it:
`beside` at `CONTACT_SLACK` means the two are touching. A negative number anywhere
means metal passes through metal, and the build says so. Fans over twelve keys
print only the five tightest.

The ring itself is one swept loop with a sleeve over the top, where the ends of a
real ring would be joined. The fan keeps clear of it.

## A ring of rings

`--nest 3` builds a larger central ring with three smaller rings hanging on it,
each one a settled bunch of keys. Nothing about it is a second model. A small
ring hanging on a big one is the same problem as a bow hanging on a ring — a loop
threaded on a wire, sinking until it rests and sliding until it meets the one
beside it — so a whole settled bunch is handed to the same solver as one more
thing to hang.

Every field a key gives the solver, a bunch gives it too: the loop that threads
on the wire, how deep the wire sits in it, the metal to keep clear of, and the
hole nothing else may pass through. The small ring stands in for the bow and its
keys come along for the ride.

**A bunch is turned, and its keys are turned back.** A small ring has to lean out
of the central ring's plane for the same reason a bow does. Leaning it carries
its keys with it, and they would render edge on. So each bunch is turned about
its own axis by `BOW_TILT_DEG`, and the keys on it are built turned by the same
angle the other way. The two cancel: the small ring leans out of the picture and
reads as an ellipse, and every key comes back square to the camera with nothing
stretched.

That is also why those keys are turned rather than sheared. A shear keeps a key's
outline true when you look along the ring's own plane, which is what a key hung
straight on a ring needs. A key that is going to be turned back needs to be true
in its own plane instead, and only a rotation leaves it that way.

**A bunch is tested as one thing.** Its metal is regrouped into fewer, larger
bounding groups than a key's, and the loop and strands the threading test reads
are thinned. Both keep a question asked of every pair on every pass from costing
what a bunch's worth of rods would cost.

| Constant | Effect |
| --- | --- |
| `NEST_COUNT`, `NEST_KEYS` | Small rings on the central one, and keys on each. |
| `NEST_WIRE_R` | Central ring stock. Heavier than a small ring's. |
| `NEST_SCALE` | How much bigger the central ring is than the small rings it carries. |
| `NEST_SPAN` | Degrees of the central ring the small rings are laid across. |
| `NEST_TILT_GAIN`, `NEST_FLARE` | How hard the small rings splay, and their front to back lean. |
| `NEST_GROUP`, `NEST_STRAND`, `NEST_POLY` | How coarsely a bunch is modeled when it is the thing being hung. |

Three bunches of five keys take about six seconds. `renders/` holds the single
bunch; the nest is not part of the packaged icon set.

## The style libraries

A key takes each style from its index, so neighbors always differ. Reorder a
cycle to change which key gets what.

| Cycle | Picks from |
| --- | --- |
| `BOW_CYCLE` | `BOW_SHAPES`: round, oval, pear, trefoil, quatrefoil, heart, plate. |
| `BIT_CYCLE` | `BIT_PATTERNS`: comb2, comb3, fine, ward, step. |
| `SHANK_CYCLE` | plain, banded, double. Every shank gets a collar, a neck, and a shoulder; the style adds rings on top. |
| `TIP_CYCLE` | dome, bore, flat. |
| `STUB_CYCLE` | How far the shaft runs past the bit. |
| `BOW_SIZE_CYCLE` | Bow scale, so no two bows match. |

A bit pattern is a dict. `cuts` are notches in the outer edge, each a start, an
end, and a depth. `shoulder` steps the top edge down near the shaft. `heel` cuts
the bottom outer corner back. A heel has to start below the last cut, or the
outline crosses itself and renders as a spike.

Add a bow by writing a function that returns a closed list of `(x, z)` points
and registering it in `BOW_SHAPES`. The rest of the key measures itself off that
outline.

## Adding keys

Raise `KEY_COUNT`, or pass `--keys N`. The bunch redistributes itself. Five keys
close up to 56 degrees, well inside the 126 degree layout. Nine spread to 106,
twelve to 158, twenty to 286 on a ring grown to 1.22, and fifty to 290 on a ring
grown to 3.13. Every one of those builds clear of itself.

A bunch that has spread as far as `FAN_MAX` allows and still overlaps is out of
wire, so the ring grows. That is why a big count ends up on a big ring: with the
keys held in one plane and none allowed to pass through another, fifty of them
genuinely need that much wire.

| Constant | Effect |
| --- | --- |
| `KEY_COUNT` | How many keys hang on the ring. |
| `HANG_SPAN` | Degrees of ring the fan is laid out across. This sets how much the keys splay, not how much wire they end up on. |
| `TILT_GAIN` | How hard the keys splay. 1.0 is fully radial; less leans them back toward plumb, as far as their holes allow. |
| `LENGTH_BASE` | Length of a key hanging at the bottom. |
| `LENGTH_GROW` | Extra length toward the edges of the fan. |
| `LENGTH_JITTER` | How far a key's length wanders off its designed one. Every key lands somewhere different in that range, so raising it staggers the bits and lets a crowded fan pack tighter. |
| `BIT_W_JITTER` | The same, for how far a bit reaches out. |
| `BOW_BASE`, `BOW_GROW` | Bow size at the edges, and how much it swells toward the middle. |
| `WIRE_R` | Bow stock radius. One thickness the whole way round, so a bow reads as evenly massive rather than heavy at one end. |
| `FLARE_SPAN` | Degrees of front to back lean across the fan, which sets the lapping order. It costs nothing head on, since leaning a key out of the picture plane only foreshortens it. |
| `BOW_TILT_DEG` | How far a bow's plane leans out of the ring's plane. |
| `RING_RADIUS` | Smallest ring the bunch may hang on. |
| `FAN_MAX` | Most of the ring a fan may wrap, which leaves the joint clear. |
| `SETTLE_PUSH`, `SETTLE_PULL` | How hard crowded keys push apart, and how hard the fan pulls back toward its layout. |
| `BOW_RODS`, `SHANK_RODS`, `BIT_RODS` | Collision rods per part. These set how closely a chain follows a curve, not how fat it reads. |
| `SETTLE_DRAW` | How hard a key slides toward the one beside it. Zero leaves the fan at its designed spacing. |
| `CONTACT_SLACK` | Daylight left wherever metal comes to rest. |

`make_keys` returns a list of plain dictionaries. Edit an entry or append one to
change a single key. `hang_deg` is a starting point that settling slides along
the wire. `tilt_deg` is honored as far as the bow's hole admits the wire.

| Field | Meaning |
| --- | --- |
| `hang_deg` | Where the bow would like to sit on the ring. 0 is the right edge, -90 is the bottom, and the angle runs counterclockwise. |
| `tilt_deg` | Lean away from straight down. Positive swings the tip right. A key keeps this lean wherever its bead ends up on the wire. |
| `flare_deg` | Lean out of the picture plane. Positive swings the tip away from the camera. |
| `length` | Bow center to tip. |
| `bow_r` | Bow size. Every shape scales off it. |
| `bow` | Bow shape name. |
| `bit`, `bit_w` | Bit cut pattern, and how far the bit reaches out. |
| `shank` | Shank ornament name. |
| `tip`, `stub` | Tip treatment, and how far the shaft runs past the bit. |
| `bit_side` | Which way the bit points. -1 is left, +1 is right. |
| `tilt_side` | Which way the key leans out of the ring's plane. |
| `turn` | Lean the key by turning it rather than by shearing it, for a bunch that is turned back the other way. |

The constants below `KEYS` set the proportions every key shares: stock
thickness, shaft radius and taper, collar size, and bit dimensions.

Every object gets one of the three entries in `PATINA`, which tint `BRASS` and
set its roughness. Neighboring keys land on different entries, so the fan reads
as separate keys rather than one casting.

Everything the script builds is plain mesh in a `KeyRing` collection, one object
per key plus the ring. Edit any of it by hand once the parameters run out, but
note that settling has already placed each object, so moving one by hand can put
it back inside its neighbor.

## Legibility

The design holds together down to about 48 pixels. At 32 it weakens, and at 16
it turns to mush — no pixel in a 16 pixel render is fully opaque, and only twenty
are at 32.

Two things drive that. The ring wire and shafts are thin, so they fall below one
pixel. The bunch is narrower than the square it renders into, so the icon wastes
its left and right margins.

Raise `RING_WIRE_R` and `SHAFT_R` to thicken the strokes. To fill more of the
square, widen `HANG_SPAN` so the keys splay harder, lower `SETTLE_DRAW` so they
stay spread along the wire, or lower `padding` in `setup_render`.

## Feeding the packaged icon

`janitor-gui/assets/icon.svg` is the current source of truth, and
`assets/gen-icons.sh` rasterizes it into `assets/icons/`. This model is not wired
into that path. The sizes `--sizes` writes match the ones that script produces,
so the files can be copied across once the design settles.

`renders/` is not committed. Copying is how a render reaches `assets/icons/`,
which is.

Note that `gen-icons.sh` also packs `icon.ico` with ImageMagick, which reads the
PNGs rather than the SVG. That step keeps working on copied files.

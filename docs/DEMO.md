# Recording the demo

Everything below is for making a three-minute video out of `python demo.py`. The
tour itself is the deliverable and it stands on its own; this is the shot list
for the version somebody watches instead of running.

Three minutes, not ten. Whoever is watching has already decided to give you one
minute and is deciding whether to give you three. The full ten-minute version is
the repository, and they can clone it.

## Before recording

Terminal at 100 columns by 44 rows, so nothing folds. A plain prompt — no git
branch, no hostname, no colour theme with a busy background. Start in a fresh
clone so the first frame is somebody arriving at this repository the way a
stranger does.

```bash
git clone https://github.com/vinayvobbili/witness && cd witness
python demo.py --pace 10
```

The run itself takes about three seconds, which is the right answer for a tool
and the wrong one for a camera. `--pace` puts a pause after each beat and each
section rule — thirteen of them — so `--pace 10` lands the whole thing a little
over two minutes, which is the cadence the beat sheet below assumes. Default is
zero. The pauses exist for the recording and for nothing else.

The timings in the beat sheet are where narration should be, not something the
run enforces. If you would rather talk over a natural-speed take, record at
`--pace 0` and put the pauses in during editing.

Do a silent take first and watch it back before recording narration. The output
is deterministic — the same captures produce the same run, the same hashes, the
same everything — so a second take is the same take. That is worth saying out
loud in the video, because it is the whole thesis in one sentence.

## The beat sheet

**0:00 — the frame.** One command, no install, no key, no image. Say the setup
cost out loud while it scrolls the evidence: six captured tool runs, two hosts,
347 records, each carrying the hash of the tool output it was parsed from. The
memory images are 3 GB and are not in the repository; what is in the repository
is what the tools said about them.

**0:20 — why this exists.** One sentence, over the first beat: autonomous
forensics agents mostly do not fail by missing evil, they fail by inventing it,
and the usual defence is a second language model that argues with the first. A
model can be talked out of a correct refutation. This uses a different kind of
oracle.

**0:35 — beat 1, the kill chain.** Admitted, six bindings, each field re-read
and compared. Say why this beat comes first: a gate that refuses everything is
not a gate, it is an off switch, so the first thing to show is that true work
survives.

**0:55 — beat 2, the fabricated C2.** `185.220.101.5` is exactly the kind of
address a confident agent reaches for. There is no record anywhere that contains
it, so there is nothing to bind to. Refused before it can be written.

**1:10 — beat 3, the one that matters.** One digit wrong — `1233` for `1332` —
against a record that really exists, cited through a tool call that really ran.
This is the frame to hold on. Every provenance-checking approach passes this
one. The claim cites a genuine `psscan` run and misstates what one row said, and
only comparing the field value catches it.

**1:30 — beat 4, gate two.** Every binding verifies. The connection is real, the
record says exactly this, the citation is perfect — and `172.16.4.10` is
RFC1918, so it is proxy egress, not command and control. Quoting the evidence
correctly and reading it wrongly is the harder failure, and gate one does
nothing about it.

**1:50 — beat 5, the gap.** Nobody ran `malfind` on this host. The claim is not
refuted and it is not admitted; it is held, and the tool that would settle it is
named. Say the line plainly: unavailable is not a pass. This is the beat that
separates a careful tool from a confident one.

**2:05 — beat 6, the honest miss.** `www.venetodns.trade` is this intrusion's
real C2 and it is refused, because in these captures the name sits in a raw
carve and in nothing that executed. Right on this evidence, a miss on this case,
and the refusal says which evidence would settle it. Do not skip this one to
make the demo look better. It is the most persuasive thing in the run.

**2:20 — beat 7, the payoff.** A hostname two decoding layers down inside a
carved command line, in something that ran, that the graded submission this
replaces never named. Decoding rather than describing found a C2 that reading
the strings dump did not.

**2:35 — replay.** Throw the case away, rebuild it from the captures alone,
compare the heads. Nothing in the store is numbered from a clock or a counter,
so the chain head is a fingerprint of the case rather than of the run. Two
people on two machines either agree on that hash or do not have the same case.
Let the two identical hashes sit on screen for a beat.

**2:50 — the close.** The two suites this run did not execute, and the fact that
it says so: 119 crafted attacks in the catalogue, and 1,083 claims in 29 classes
of ordinary analytical error scored for precision, recall, and whether each
refusal named the actual defect. Then stop. Do not read the numbers out as
results in a video that did not run them.

## Recording it

`asciinema` is the right tool — it captures text rather than pixels, the result
is a fraction of the size, and a viewer can select and copy from it.

```bash
asciinema rec witness-demo.cast --command "python demo.py --pace 10"
asciinema upload witness-demo.cast
```

For a file that plays anywhere without a service, `agg` turns a cast into a GIF:

```bash
agg --font-size 15 --theme monokai witness-demo.cast witness-demo.gif
```

Screen capture with voiceover works too and is worth the extra effort for the
version that goes on a job application, because the narration above is doing
half the work. Keep the terminal filling the frame — nobody needs to see the
desktop.

## Things not to do

Do not trim the refusals to fit. The refusals are the product; a cut that keeps
the two admitted findings and drops the five refused ones has removed the
argument and left the demo.

Do not speed the footage up through the beats. The point of a beat is that a
viewer reads the claim and the verdict, and a sped-up refusal is a colour
change.

Do not add a voiceover claim the run does not show. It would be a strange thing
to get wrong in a video about a tool that refuses claims it cannot bind, and it
is exactly the kind of thing that happens at 1 a.m. the night before a deadline.

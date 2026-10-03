# Release checklist (v1.0.0, DOI)

> Status 2026-10-03: steps 1–9 completed. v1.0.0 (commit `b51f048`) is published on
> GitHub and archived by Zenodo, DOI 10.5281/zenodo.23122101. Step 10 (metadata) is
> applied on `main`; steps 11–12 belong to the manuscript revision round.

The public repository is released only after every step below is completed in
order. Nothing is pushed, released or archived until the authors approve it.
No DOI, URL or accession number is written into any file until it exists.

1. **Final local audit.** `python3 reproducibility/verify_release.py` reports no
   FAIL. `git status` is clean apart from the commit being prepared. No file
   listed in `.gitignore`'s secret/weight/raw-data sections exists in the tree.
2. **Clean-clone test.** Clone (or copy the tracked files) into an empty
   directory and run step 3 and 4 there, so nothing depends on untracked files
   or on the authors' machine.
3. **Dependency installation from scratch.**
   `python3 -m venv .venv && . .venv/bin/activate && pip install -r reproducibility/environment/requirements.txt`
4. **Reproduction tests.** In the clean clone:
   `python3 reproducibility/verify_release.py` (public path), and, by an author
   holding the restricted exports,
   `python3 reproducibility/verify_release.py --operator-exports <dir> --cpe-dictionary <official dictionary>`
   to confirm Tables 2–7 regenerate the released values.
5. **Security/history scan.** Repeat the working-tree and `git log --all`
   scan for credentials, customer identifiers, raw inventories, spreadsheets,
   model weights and internal paths. Nothing may be pushed if any is found.
6. **Push the approved commit** to `main` of the public repository.
7. **GitHub release `v1.0.0`** from that commit.
8. **Archive the release in Zenodo** (GitHub–Zenodo integration, or manual
   upload of the release archive). Zenodo metadata: title and authors as in
   `CITATION.cff`; licence MIT for code/data; related identifier "is supplement
   to" the manuscript once it has a DOI.
9. **Obtain the real DOI** from Zenodo (concept DOI for all versions and the
   version DOI for v1.0.0).
10. **Insert the real DOI / repository citation** into:
    - `README.md` (Citations section),
    - `CITATION.cff` (`doi:`, `date-released:`, `repository-code:`),
    - `CODE_AVAILABILITY.md`,
    - `DATA_AVAILABILITY.md` (if the data citation is separate),
    - the manuscript's Data Availability statement (replace "provided as
      supplemental files with this submission" with the repository URL and
      DOI; the sentence "See DATA_AVAILABILITY.md and CODE_AVAILABILITY.md in
      the supplemental files" must then point at the repository),
    - the PeerJ declaration / submission question on data and code.
11. **Rebuild the final manuscript PDF** from the edited `main.tex` and copy it
    to `paper/PeerJ_Manuscript.pdf`; commit as a new version (v1.0.1 or v1.1.0)
    and archive that version too if the DOI is expected to resolve to the
    final text.
12. **Final consistency audit**: every file that names the DOI, repository URL,
    version and release date agrees; `verify_release.py` still passes.

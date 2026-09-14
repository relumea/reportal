# Command reference

Every `reportal` command, its options and what it writes.  `reportal --help`
and `reportal <command> --help` are generated from the same Typer app and are
the authority when the two disagree; README.md carries worked examples.

```bash
reportal init [--dir PATH]                 # write reportal.toml + reportal.db
reportal import-rebrew <project-dir>       # ingest a rebrew workspace (idempotent; stores its context)
                                           #   plus the target binary's import stubs as THUNK rows
reportal add-binary <path> [--name TEXT]   # register a binary by sha256 (dedupe)
reportal download <binary-id> [--analysis] [--output PATH] [--force] [--zip] [--password TEXT] [--json]
                                           # write the stored binary's bytes to a path (default:
                                           #   the stored name in the current directory), copying
                                           #   in bounded chunks; --zip writes a zip whose member
                                           #   is password protected instead (default password
                                           #   'infected', a shared convention, not a secret);
                                           #   --analysis reads the id as an analysis id and
                                           #   writes that analysis's binary
reportal sandbox <binary-id> [--timeout N] [--memory-mb N] [--report|--status] [--json]
                                           # detonate a stored sample under the sandbox
                                           #   runner (off by default: the workspace opts in
                                           #   and a runner must be installed); --report
                                           #   prints the stored one, --status says whether
                                           #   a run is possible here
reportal firmware <binary-id> [--json]       # carve a stored firmware image: its embedded
                                           #   regions, their entropy and confidence;
                                           #   offline byte work, nothing executed
reportal firmware-extract <binary-id> [--region N]... [--collection ID] [--json]
                                           # carve regions out as binaries; a gzip, tar or
                                           #   zip region is unpacked, the rest are stored
                                           #   as binaries of their own; one journal action
reportal extract <binary-id> [--password TEXT] [--collection ID] [--json]
                                           # unpack a stored archive with the stdlib
                                           #   (zip/apk, tar/tar.gz/tgz/tar.bz2/tar.xz, gz),
                                           #   register each member by content hash into one
                                           #   collection and report each member and refusal;
                                           #   one journal action, reverted with the printed id
reportal scans <binary-id> [--json]        # each stored scan of the binary's
                                           #   newest analysis with the inputs it
                                           #   ran with, so a reading can be run
                                           #   again the same way
reportal config [--json]                  # what this install can do, and every
                                           #   setting reportal reads with the
                                           #   origin that answered; names the keys
                                           #   and values reportal does not read and
                                           #   exits 1 on a file it cannot parse
reportal doctor [--port N] [--json]        # readiness before a start: workspace,
                                           #   database, schema, auth, engine, SPA
                                           #   build, optional paths, free port; exits
                                           #   1 on a failure, 0 on a warning
reportal backup [--output PATH] [--json]    # write the whole workspace (database,
                                           #   binaries, reports) as one gzipped
                                           #   tar; the database is copied through
                                           #   SQLite's own backup API
reportal restore ARCHIVE [--overwrite] [--yes] [--json]
                                           # read an archive back into this
                                           #   workspace; it is staged and checked
                                           #   against its manifest first, so a
                                           #   refused archive changes nothing
reportal backup-info ARCHIVE [--json]      # one archive's manifest, without
                                           #   restoring it
reportal symbols <binary-id> <path> [--no-apply] [--json]
                                           # ingest a PDB or ELF/DWARF symbol file:
                                           #   parse it, rename the functions whose
                                           #   VA matches a symbol and add the types
                                           #   it declares, as one journal action
reportal symbols-status <binary-id> [--file-id N] [--json]
                                           # the ingested symbol files, or one in
                                           #   full with its notes and its symbols
reportal symbols-export <binary-id> [--format c|json] [--output PATH] [--file-id N]
                                           # render one parse as a C header (through
                                           #   the type model's renderer) or as JSON
reportal enrich <binary-id>                # compute and store a rebrew fingerprint
reportal decompile <function-id> [--backend kuna] [--named] [--json]
                                           # decompile through rebrew and store the source
reportal summary <function-id> [--json]    # summarize the stored decompilation with the
                                           #   configured LLM and store the result
reportal comments --binary ID | --function ID [--json]
                                           # list the analyst comments stored on a binary or
                                           #   function (oldest first)
reportal comment-add --binary ID | --function ID "text" [--author NAME] [--json]
                                           # store one analyst comment; the author defaults to
                                           #   comments.DEFAULT_AUTHOR
reportal comment-rm <comment-id> [--json]  # delete one analyst comment
reportal bulk-tag <tag> <binary-id>... [--remove] [--json]
                                           # add or remove one tag across many binaries
reportal bulk-delete <binary-id>... [--yes] [--json]
                                           # delete many binaries and everything scoped to them;
                                           #   asks for confirmation unless --yes is passed
reportal bulk-prefix <prefix> <function-id>... [--replace] [--json]
                                           # prefix many function names through the normal
                                           #   rename path, recording each in history; --replace
                                           #   drops the name's leading segment first
reportal ai-comments <function-id> [--json]
                                           # inline comments from the configured LLM, stored
reportal suggest-types <function-id> [--json]
                                           # parameter/return/local type suggestions, stored
reportal suggest-renames <function-id> [--json]
                                           # identifier renames from the configured LLM,
                                           #   stored over the function's decompilation
reportal apply-renames <function-id> [--all|--from NAME --to NAME] [--rename-function] [--json]
                                           # rewrite whole-token identifiers in the stored
                                           #   decompilation, journaling the previous text so
                                           #   the apply can be reverted; --rename-function
                                           #   also renames the function row
reportal revert-renames <function-id> [--json]
                                           # restore the decompilation text the last apply journaled
reportal ai-decompile <function-id> [--json]
                                           # ask the configured LLM for a whole rewritten function
                                           #   over the stored decompilation and store the artifact
                                           #   with its token map and per-line attributions
reportal ai-decompilation <function-id> [--json]
                                           # the stored rewrite rendered with its token overrides
reportal ai-decompilation-status <function-id> [--json]
                                           # the artifact's counts, model, rating and times
reportal ai-tokens <function-id> [--json]  # the placeholder tokens and the name each one carries
reportal ai-lines <function-id> [--json]   # each rewritten line's attribution (original/rewritten/
                                           #   added) and the source lines it paired with
reportal ai-override <function-id> <token> [<name>] [--clear] [--json]
                                           # set or clear an analyst name for one placeholder token;
                                           #   the stored rewrite itself is never changed
reportal ai-rate <function-id> [<rating>] [--note TEXT] [--json]
                                           # record analyst feedback (up/down, empty to clear)
reportal ai-line-comments <function-id> [--json]
                                           # the per-line inline comments stored beside the artifact
reportal ai-line-comment-add <function-id> <line> <body> [--author NAME] [--json]
reportal ai-line-comment-edit <function-id> <line> <body> [--json]
reportal ai-line-comment-rm <function-id> <line> [--json]
                                           # add, edit or remove the comment stored at a line
reportal signatures-batch <function-id>... [--json]
                                           # signatures for many functions in one read, in the
                                           #   order the ids were given (at most 200)
reportal signature-copy <analysis-id> <source-id> <target-id>... [--json]
                                           # copy one function's signature onto others in the
                                           #   analysis, journaled per target
reportal data-types-import <analysis-id> [--definition DECL]... [--file PATH] [--update-only] [--json]
                                           # create or update types from C declarations; a struct
                                           #   may span lines, and --update-only refuses a name
                                           #   the binary does not carry yet
reportal data-type-functions <analysis-id> <data-type-id> [--json]
                                           # the functions that use one data type, from the
                                           #   stored reference index
reportal indirect-calls <function-id> [--json]
                                           # the indirect calls and jumps in the function's
                                           #   cached listing (no cached listing reports none
                                           #   rather than running the engine)
reportal function-capabilities <function-id> [--json]
                                           # classify one function from the imports and
                                           #   literals its stored decompilation mentions
reportal function-strings <function-id> [--json]
                                           # the analyst strings recorded for the function,
                                           #   and the literals its decompilation carries
reportal user-string-add <function-id> <value> [--kind KIND] [--note TEXT] [--json]
reportal user-string-rm <function-id> <string-id> [--json]
                                           # add or remove one analyst string; journaled
reportal analysis-strings <analysis-id> [--json]
                                           # every analyst string recorded at analysis scope
reportal analysis-strings-set <analysis-id> <value>... [--json]
                                           # replace the whole list in one journaled action
reportal callee-add <function-id> <callee> [--kind call|indirect] [--note TEXT] [--json]
reportal callee-rm <function-id> <edge-id> [--json]
                                           # record or remove one analyst-declared callee edge
reportal callees-callers <function-id>... [--json]
                                           # the derived callers and callees of many functions
                                           #   in one read (at most 50 ids), plus the declared
                                           #   edges; a text derivation over stored rows
reportal canonical-names <function-id>... [--dry-run] [--json]
                                           # rename functions to the candidate the store
                                           #   already recorded; a function with none is
                                           #   skipped rather than renamed to a guess
reportal function-matches <function-id>... [--json]
                                           # the recorded match rows of many functions in one
                                           #   read; runs no scoring and no engine
reportal external-sources [--json]          # the external-source registry, with each
                                           #   source's kind and availability
reportal external <analysis-id> [--source NAME] [--json]
                                           # run one source and store its answer (journaled);
                                           #   the offline source reads stored rows, a remote
                                           #   one needs the opt-in and a key
reportal external-status <analysis-id> [--source NAME] [--json]
                                           # whether the source can run and what is stored
reportal secrets-list [--scope local|team] [--team-id N] [--json]
                                           # the stored credentials, redacted: the value is
                                           #   never printed, only the name, scope, byte
                                           #   length and a last-four hint
reportal secrets-set <name> [<value>] [--stdin] [--scope local|team] [--team-id N] [--json]
                                           # store or replace one credential, journaled so a
                                           #   rotation reverts; --stdin reads the value from
                                           #   stdin, which keeps it out of the shell history
reportal secrets-rm <name> [--scope local|team] [--team-id N] [--json]
                                           # remove one credential; a revert restores it
reportal models [--json]                  # the model registry: what can produce a stored
                                           #   result, with its kind, version and availability
reportal analysis-upgrade <analysis-id> --model NAME [--function ID]... [--limit N] [--json]
                                           # re-run the analysis's stored AI artifacts under a
                                           #   different llm model, journaling every replacement;
                                           #   reportal never re-analyses the binary
reportal conversation-run <conversation-id> <message> [--json]
                                           # run one agent turn: the model may call
                                           #   the local MCP tools and then answer;
                                           #   a destructive call pauses the run
reportal conversation-runs <conversation-id> [--json]
                                           # every agent run of one conversation
reportal conversation-run-status <conversation-id> [--run-id N] [--json]
                                           # one run's status, events, pending call
                                           #   and answer
reportal conversation-confirm <conversation-id> [--reject] [--run-id N] [--json]
                                           # approve or reject the pending tool call
                                           #   and continue the run
reportal conversation-cancel <conversation-id> [--run-id N] [--json]
                                           # stop a live run at its next step
reportal conversation-events <conversation-id> [--run-id N]
                                           # follow the run's state as SSE frames
reportal pipeline <function-id> [--json]   # run the component AI decompilation pipeline over one
                                           #   function, storing the run and its artifacts
reportal pipeline-revert <run-id> [--json] # undo exactly what one stored run wrote
reportal components [--json]               # list the component registry: name, requires,
                                           #   provides, origin, reloadable
reportal components-reload [NAME] [--all] [--json]
                                           # re-read one component's declaring module (or every
                                           #   reloadable one) and swap the live registry entry
reportal components-deactivate <name> [--json]
                                           # withdraw a component from the live composition:
                                           #   run its revert where declared, revoke the names
                                           #   it provided and report what it journaled
reportal integrations [--json]             # list every plugin seam with the parts its registry
                                           #   currently holds
reportal auto <binary-id> [--worker offline|llm_c_source] [--execute] [--concurrency N]
             [--functions-per-task N] [--max-attempts N] [--max-tasks N] [--recover] [--json]
                                           # decompose a binary's unmatched functions into batches,
                                           #   work them and report the coverage delta; dry-run by
                                           #   default, --execute writes C files into the rebrew
                                           #   project and compiles them, --recover closes the
                                           #   binary's latest stale run first
reportal auto-recover <run-id> [--json]    # close a run a dead process left `running`, merging the
                                           #   writes its unfinished tasks recorded into its plan
reportal auto-revert <run-id> [--json]     # remove the files one stored auto run wrote, restore the
                                           #   statuses it changed and delete its rows
reportal conversations [--json]            # list stored conversations
reportal chat-new --function <id> | --binary <id> [--title TEXT] [--json]
                                           # open a chat scoped to a function or binary
reportal chat <conversation-id> "message" [--json]
                                           # send one message through the LLM bridge and print
                                           # the reply
reportal xrefs <function-id> [--kind NAME]... [--json]
                                           # list a function's cross-references (live, not stored)
reportal structs <binary-id> [--decompiler kuna] [--limit N] [--json]
                                           # recover struct definitions and store the result
reportal types <binary-id> [--json]        # list the editable type model with sizes and offsets
reportal types <binary-id> [--source LABEL] [--json]
                                           # the editable type model with each
                                           #   type's provenance (System, User,
                                           #   Auto Unstrip, AI) and the count per
                                           #   label
reportal types-import <binary-id> [--json]
                                           # seed the model from the stored structs scan
reportal type-rename <type-id> <new-name> [--json]
                                           # rename one data type
reportal type-kind <type-id> <kind> [--json]  # switch the declaration kind
reportal type-namespace <type-id> <namespace> [--json]
                                           # set the namespace (empty clears it)
reportal type-size <type-id> <size> [--json]  # declare the size; the printed check
                                           #   names both numbers when they disagree
reportal type-member <type-id> <member> [--new-name N] [--new-type T]
                     [--new-bits N | --clear-bits] [--new-count N | --clear-count]
                     [--pointer | --no-pointer] [--json]
                                           # reshape one member (a retype keeps its bits)
reportal type-member-add <type-id> <name> <type> [--pointer] [--count N] [--bits N]
                         [--index N | --after NAME] [--json]
                                           # add a member at a position
reportal type-member-gap <type-id> <member> [--size N] [--json]
                                           # convert a member to padding
reportal type-member-ungap <type-id> <member> <name> <type> [--pointer] [--count N]
                           [--bits N] [--json]
                                           # convert padding back to a member
reportal type-value-add <type-id> <name> [--value V] [--json]
                                           # add an enum constant (V decimal or 0x hex;
                                           #   omitted, it increments and says so)
reportal type-value-edit <type-id> <value> [--new-name N] [--new-value V] [--json]
                                           # rename and/or revalue an enum constant
reportal type-value-remove <type-id> <value> [--json]
                                           # remove an enum constant
reportal types-export <binary-id> <path> [--force] [--json]
                                           # render the model as one C header at an explicit path
reportal types-history <type-id> [--json]  # list a type's edits, newest first, with each
                                           #   version's per-field diff (a deleted type's
                                           #   history is still listed)
reportal types-revert <type-id> <history-id> [--json]
                                           # restore the state one history row recorded; the
                                           #   revert is journaled and a repeat is a no-op
reportal signatures <binary-id> [--json]   # list the stored function signatures
reportal signatures-import <binary-id> [--json]
                                           # parse the binary's stored decompilations into the model
reportal signature <function-id> [--json]  # show one signature and its rendered prototype
reportal signature-set <function-id> [--return-type T] [--convention C] [--json]
                                           # set the return type and/or calling convention
reportal signature-param <function-id> <index> [--type T] [--name N] [--at SLOT] [--kind K]
             [--bits N] [--clear FIELD] [--json]
                                           # edit one parameter's type, name, arrival location,
                                           #   kind or width; --clear empties a field
reportal signature-param-move <function-id> <index> <to-index> [--json]
                                           # reorder one parameter, recomputing the arrival
                                           #   locations the calling convention implies
reportal signature-param-add <function-id> [--type T] [--name N] [--index I] [--json]
                                           # add a parameter, appended or at an index
reportal signature-param-rm <function-id> <index> [--json]
                                           # remove one parameter, reindexing the rest
reportal signatures-export <binary-id> <path> [--force] [--json]
                                           # render one prototype header at an explicit path
reportal signature-history <function-id> [--json]
                                           # list a function's signature-edit history, newest
                                           #   first, with the state each edit replaced
reportal signature-revert <function-id> <history-id> [--json]
                                           # restore the state one signature-history row
                                           #   recorded; the revert is journaled and a repeat is
                                           #   a no-op
reportal memory <binary-id> <address> [--length N] [--offset-kind va|rva|file] [--json]
                                           # read a window of the binary's bytes through the
                                           #   engine (default 64 bytes, cap 1024, the hosted
                                           #   portal's read_memory bounds)
reportal memory-page <binary-id> [address] [--length N] [--offset-kind va|rva|file] [--json]
                                           # page the binary's bytes for the full-file view;
                                           #   each page states a gap rather than zeros where
                                           #   the engine's section map backs no bytes
                                           #   (default 256, cap 4096)
reportal references <function-id> [--json]
                                           # list a function's globals, callers and callees
                                           #   through the engine's describe call
reportal strings <binary-id> [--sort value|length] [--order asc|desc] [--json]
                                           # list a binary's strings, sorted server-side
reportal section-coverage <binary-id> [--json]
                                           # report per-section byte coverage over the stored
                                           #   function table and the stored pe-info sections;
                                           #   reportal's own metric, not a portal feature
reportal match <binary-id> [--min-similarity 80] [--top 10] [--json]
                                           # rank each function against the local corpus
reportal triage <binary-id> [--json]       # store the rebrew one-shot dossier
reportal function-triage <binary-id> [--limit N] [--function ID]... [--json]
                                           # score and summarize the binary's selected
                                           #   functions (configured LLM, else the
                                           #   deterministic heuristic) and store the result
reportal crypto-scan <binary-id> [--json]  # detect crypto constants and APIs, store the result
reportal pe-info <binary-id> [--json]      # inspect a binary's PE identity, sections, security
                                           #   flags, signature, debug and Rich-header metadata,
                                           #   store the result
reportal die-info <binary-id> [--json]     # the Detect-It-Easy shaped identity (format, arch,
                                           #   bits, mode, entry point) beside the packer,
                                           #   protector, installer, runtime and toolchain
                                           #   matches, each with its confidence and signals,
                                           #   plus the fingerprint entropy; a read of the
                                           #   stored scans, so it runs no engine
reportal additional-details <binary-id> [--status] [--json]
                                           # the overlay past the last section, the Rich
                                           #   header, the debug entries, the directory
                                           #   presence and the section shape; --status
                                           #   reports which sources are stored instead,
                                           #   and never fails on an uninspected binary
reportal filetype <binary-id> [--json]     # detect file type, packer and protector signatures
                                           #   over the pe-info sections and entry point, the
                                           #   section entropies, the imports and the strings,
                                           #   store the result
reportal capabilities <binary-id> [--json] # classify a binary from its imports and strings
                                           # (deterministic rule table, no LLM), store the result
reportal secrets <binary-id> [--json]      # scan a binary's strings for credential patterns and
                                           # high-entropy blobs, store the findings; values are
                                           # sensitive and are redacted in human output
reportal protocols <binary-id> [--json]    # infer the network protocols from the imports
                                           # (dedicated APIs and the generic socket family),
                                           # URL schemes and protocol literals, plus the
                                           # host:port rule, and store the result
reportal behavior <binary-id> <domain> [--json]
                                           # match execution, networking or filesystem
                                           # rules over the imports and strings; --all runs
                                           # all three domains
reportal hardening <binary-id> <domain> [--json]
                                           # match the anti-analysis rules or apply the
                                           # obfuscation thresholds over the fingerprints,
                                           # imports, strings and stored triage; --all runs
                                           # both domains
reportal security-scan <binary-id> [--min-severity high|medium|low] [--json]
                                           # scan the rebrew project's reversed C sources for
                                           # unsafe API use, store the findings
reportal threat <binary-id> [--narrative] [--json]
                                           # extract IOCs from the binary's strings, map them and
                                           # its imports/capabilities to ATT&CK, store the report;
                                           # --narrative adds an LLM analyst summary when configured
reportal yara <binary-id> [--output PATH] [--json]
                                           # generate a YARA rule from the binary's strings and
                                           # imports (PE rules anchor on the fingerprint's
                                           # imphash), print its specificity, validate it with
                                           # yarac (optional) and store it; --output writes the
                                           # rule atomically to PATH
reportal snort <binary-id> [--output PATH] [--json]
                                           # render one Snort rule per URL/domain/IPv4
                                           # indicator the stored threat scan names (destination
                                           # port from the indicator or the stored protocols
                                           # scan, else any), print the rule count and store the
                                           # remediation scan; --output writes the rules to PATH
reportal stix <binary-id> [--output PATH] [--json]
                                           # render a deterministic STIX 2.1 bundle over the
                                           # stored threat scan's indicators (a note object when
                                           # there are none), print it and store the remediation
                                           # scan; --output writes the bundle to PATH
reportal report <binary-id> [--json]       # generate the rebrew HTML report into the
                                           # workspace and store the engine result
reportal report-pdf <binary-id> [--output PATH] [--force] [--queue|--status] [--json]
                                           # --queue submits a report-pdf job instead of
                                           #   waiting; --status reports the stored file
                                           #   and the newest report-pdf job
                                           # render a text-only PDF summary from the
                                           # stored scans; default output is
                                           # <workspace>/reports/<id>/report.pdf, --output
                                           # writes elsewhere and refuses to overwrite
                                           # without --force
reportal library <binary-id> [--min-confidence F] [--json]
                                           # identify which libraries the
                                           #   engine's signature match finds in
                                           #   a binary and store the module
                                           #   rollup; needs a rebrew project
reportal sbom <binary-id> [--format cyclonedx|spdx|csv] [--output PATH] [--json]
                                           # export the stored library reading
                                           #   as a bill of materials; stored-only,
                                           #   it never re-runs the engine
reportal benchmark <left-id> <right-id> [--labels FILE] [--top N]
                   [--min-similarity F] [--min-confidence F] [--json]
                                           # score a match run against
                                           # known counterpart addresses;
                                           # without --labels the ground
                                           # truth is the two binaries'
                                           # shared real function names
reportal rename-benchmark <binary-id> [--json]
                                           # score the stored rename
                                           # proposals against the names an
                                           # ingested debug symbol file
                                           # supplied; stored-only
reportal benchmark-info <binary-id> [--json]
                                           # show the stored benchmark:
                                           # precision, recall, F1, MRR
                                           # and the missed labels
reportal unpack <binary-id> [--packer lzexe|upx] [--name TEXT] [--json]
                                           # rebuild a packed executable's
                                           # image and register it as a binary
                                           # of its own; the packer is detected
                                           # from the file's own stub unless
                                           # named; LZEXE runs in process
                                           # through the engine, UPX needs the
                                           # external upx tool, and nothing is
                                           # executed
reportal unpack-info <binary-id> [--json]
                                           # show where an unpacked binary came
                                           # from: the packed source, the
                                           # packer, the method and the sizes
reportal unstrip <binary-id> [--min-confidence F] [--json]
                                           # store rename proposals for library-identified
                                           # functions (rebrew identify-library --dry-run)
reportal unstrip-apply <function-id> [--name TEXT] [--json]
                                           # apply one stored unstrip proposal, recording
                                           # the rename with source unstrip
reportal revert <function-id> <history-id> [--json]
                                           # restore the name a history row replaced
reportal tags [--json]                     # list tags with tagged-binary counts
reportal tag <binary-id> <name> [--remove] [--json]
reportal collections [--order ORDER] [--json]
                                           # list collections with member and tag counts,
                                           #   sorted by id (default), name, size or updated
reportal collection-show <collection-id> [--json]
                                           # one collection with its members and tags
reportal collection-new <name> [--description TEXT] [--scope TEXT] [--json]
                                           # create a collection
reportal collection-edit <collection-id> [--name TEXT] [--description TEXT] [--scope TEXT]
                         [--json]          # set the fields given; absent ones stay
reportal collection-rm <collection-id> [--json]
                                           # delete a collection with its membership and tags;
                                           #   the printed journal action reverts it
reportal collection-add <collection-id> <binary-id>... [--json]
                                           # add members, keeping the ones already in it
reportal collection-remove <collection-id> <binary-id>... [--json]
                                           # remove members, keeping the others
reportal collection-tags <collection-id> [tag]... [--json]
                                           # replace the collection's tags (none clears them)
                                           # add or remove one tag by name
reportal apply-match <function-id> <candidate-function-id> [--mode name|signature|both]
             [--json]                      # transfer a recorded match candidate onto the
                                           #   function: its name, its signature, or both
reportal diff <function-id> <candidate-function-id> [--kind disasm|decomp]
             [--no-normalize] [--json]     # align a function against a match candidate
                                           #   side by side: a unified-style listing with
                                           #   changed lines marked and the summary counts
reportal lineage <left-binary-id> <right-binary-id> [--no-refine] [--json]
                                           # compare two binaries' functions pairwise and
                                           #   report unchanged, changed, added and removed;
                                           #   --no-refine skips the structural pass
reportal related <binary-id> [--limit N] [--all] [--json]
                                           # rank the other stored binaries by their
                                           #   relationship to this one (hashes, imports,
                                           #   capabilities, size); --all keeps the unrelated
reportal composition <binary-id> [--binary-id N]... [--collection-id N]... [--json]
                                           # summarize how this binary's functions match the
                                           #   stored corpus (matched counts, name sources,
                                           #   quality bands, the hosted categories, the
                                           #   per-binary rollup) from the matches table only;
                                           #   the scope options narrow the candidates like
                                           #   the match settings sheet; no engine, no matching
reportal families [--json]                 # list the locally registered malware families
reportal family-add <reference-binary-id> <name> [--alias TEXT]... [--notes TEXT] [--json]
                                           # derive a reference binary's signature bundle and
                                           #   register a family from it
reportal family-rm <family-id> [--json]    # delete a registered family
reportal detect <binary-id> [--json]       # match a binary against the registered families and
                                           #   store the detection; no external intel feed is used
reportal ingest <binary-id> <path> [--title TEXT] [--json]
                                           # chunk and store a local text file in the
                                           #   binary's knowledge scope
reportal ingest-url <binary-id> <url> [--title TEXT] [--project] [--json]
                                           # fetch an http(s) URL and store its text in the
                                           #   binary's scope, or the project scope with
                                           #   --project; off by default (REPORTAL_ALLOW_REMOTE_INGEST
                                           #   or [knowledge] allow_remote = true)
reportal documents <binary-id> [--json]    # list the knowledge documents of one binary
reportal knowledge <binary-id> "query" [--limit N] [--json]
                                           # rank the scope's document chunks against the
                                           #   query (embeddings, else local TF-IDF)
reportal context <function-id> [--query TEXT] [--json]
                                           # retrieve the function's binary documents ranked
                                           #   against the query (default: the function name)
reportal graph-build <binary-id> [--json]  # rebuild the knowledge graph from the stored rows
reportal graph <binary-id> [--json] [--node ID]
                                           # node counts by kind (the whole stored graph,
                                           #   documents included), or one node's neighbor
                                           #   groups grouped by relation
reportal graph-backends [--json]           # list the registered graph backends: name,
                                           #   available, description/unavailable reason, query
reportal graph-sync <binary-id> [--backend NAME] [--json]
                                           # push a binary's stored graph to a backend
                                           #   (default: the configured one); the built-in
                                           #   sqlite backend reports the local counts, the
                                           #   optional cognee backend pushes a dataset
reportal graph-query <query> [--backend NAME] [--json]
                                           # node id or text search over a backend that
                                           #   supports querying (sqlite does)
reportal jobs [--status S] [--kind K] [--limit N] [--json]
                                           # queued and finished operations, newest first,
                                           #   with the waiting count and the kinds
reportal job <job-id> [--json]             # one job with its status, progress and result
reportal job-submit <kind> <binary-id> [--domain D] [--run] [--json]
                                           # queue one operation; the server's pool runs it,
                                           #   or --run does it in this process
reportal job-run [--limit N] [--json]      # run the oldest waiting jobs inline
reportal job-cancel <job-id> [--json]      # cancel a job that has not started
reportal notifications [--json] [--since ISO] [--limit N]
                                           # the notification feed derived from the action
                                           #   journal and the analysis log, newest first;
                                           #   reads only, stores nothing, and prints the
                                           #   latest time to pass back as --since
reportal journal [--json] [--action ID] [--limit N]
                                           # list recorded action-journal entries, newest
                                           #   first, optionally narrowed to one action
reportal journal-revert --action ID | --entry ID [--json]
                                           # replay one recorded action's or one entry's
                                           #   stored inverses; a wired command prints its
                                           #   action id to stderr (or in --json output)
reportal rate <binary-id> <kind> [<verdict>] [--note TEXT] [--json]
                                           # thumbs up/down on one stored agent
                                           #   artifact; an empty verdict clears
                                           #   it and the write is journaled
reportal ratings <binary-id> [--json]      # every stored agent artifact with the
                                           #   verdict on it
reportal search <query> [--kind K] [--limit N] [--regex] [--json]
                                           # search binaries, functions,
                                           #   collections and tags: a substring by
                                           #   default, a bounded regular
                                           #   expression with --regex, or one
                                           #   typed query (sha256, binary,
                                           #   collection, tag)
reportal stats [--series] [--days N] [--json]
                                           # row counts, or the dashboard time
                                           #   series with --series: analyses,
                                           #   auto runs, journaled actions and
                                           #   software types per day
reportal docs [<slug>] [--json]            # the shipped documentation pages,
                                           #   or one of them parsed into
                                           #   headings, paragraphs, lists,
                                           #   code, quotes and tables
reportal changelog [--json]                # the changelog (CHANGELOG.md)

reportal activity [--actor NAME] [--since ISO] [--limit N] [--json]
                                           # what was done here and by whom: the journaled
                                           #   actions with their actor plus the analysis log
reportal feedback [--limit N] [--json]     # the local feedback notes, newest first
reportal feedback-add MESSAGE [--json]     # store one feedback note; journaled
reportal teams [--json]                    # the teams with their member counts
reportal team-add NAME [--description TEXT] [--json]
                                           # create a team; journaled
reportal team-rm <team-id> [--yes] [--json]
                                           # delete a team; the objects it owned
                                           #   return to the whole workspace
reportal team-member <team-id> <user-id> [--remove] [--json]
                                           # add or remove a membership; journaled
reportal team-role <team-id> <user-id> [owner|member] [--json]
                                           # set one member's team role: an
                                           #   owner manages the team; journaled
reportal organisations [--json]            # the organisations and the teams each
                                           #   holds; a grouping, not access
reportal organisation-add NAME [--description TEXT] [--json]
                                           # create an organisation; journaled
reportal organisation-rm <organisation-id> [--json]
                                           # delete an organisation; its teams stay
reportal team-organisation <team-id> [<organisation-id>] [--json]
                                           # move a team into an organisation, or
                                           #   ungroup it by omitting the id
reportal binary-scope <binary-id> [--visibility public|team] [--team ID] [--json]
                                           # who may see one binary; journaled
reportal collection-scope <collection-id> [--visibility public|team] [--team ID] [--json]
                                           # who may see one collection; journaled
reportal users [--json]                    # local users with their roles and state;
                                           #   never a token digest
reportal user-add <name> [--role viewer|analyst|admin] [--json]
                                           # create a user and print its token once
                                           #   (only the digest is stored); journaled
reportal user-token <user-id> [--json]     # replace a user's token, printed once
reportal user-edit <user-id> [--role R] [--disable|--enable] [--json]
                                           # set the role or the disabled state; journaled
reportal user-rm <user-id> [--yes] [--json]
                                           # delete a user; journaled
reportal config [--json]                   # what this instance can do: versions,
                                           #   features, limits and MCP tool counts;
                                           #   needs no workspace
reportal analyses [--status S]... [--workspace W] [--platform P] [--arch A]
             [--search TEXT] [--order O] [--limit N] [--json]
                                           # the analyses list with each row's
                                           #   owner team and visibility; the
                                           #   workspace filter is personal,
                                           #   team or public, --status repeats
                                           #   as any-of, --platform/--arch match
                                           #   the binary and --order takes
                                           #   newest, oldest, name or size
                                           #   (with -desc)
reportal analysis <id> [--status|--params|--func-maps|--tags] [--json]
                                           # one analysis: its detail, or its lifecycle,
                                           #   its re-run parameters, its function map or
                                           #   the tags on its binary
reportal analysis-update <id> --engine TEXT [--json]
                                           # relabel the analysis's engine; journaled
reportal analysis-log <id> MESSAGE [--severity info|warn|error] [--json]
                                           # append one log entry; journaled
reportal analysis-requeue <id> [--json]    # back to pending, finish time cleared, logged
reportal analysis-tags <id> NAME... [--json]
                                           # replace the tags on the analysis's binary
reportal imported-functions <id> [--limit N] [--json]
                                           # the analysis's import stubs, each with the
                                           #   functions whose stored decompilation
                                           #   mentions it (text derived callers)
reportal analyses [--status S] [--search TEXT] [--order newest|oldest]
             [--limit N] [--json]
                                           # list analyses with their binary, status,
                                           #   size, tags and log tail; an unknown
                                           #   status/order or an out-of-range limit fails
reportal analysis-logs <analysis-id> [--limit N] [--offset N] [--json]
                                           # one analysis's structured log, newest first,
                                           #   with the log's true total
reportal analysis-delete <analysis-id> [--json]
                                           # delete one analysis with its functions, scans
                                           #   and log; journaled, and refused (exit 1) for
                                           #   a binary's only analysis while it holds functions
reportal analysis-bulk-tag TAG <analysis-id>... [--remove] [--json]
                                           # add or remove one tag across the binaries
                                           #   many analyses belong to; journaled as one action
reportal analysis-bulk-delete <analysis-id>... [--yes] [--json]
                                           # delete many analyses with the rows scoped to
                                           #   them; a binary's only analysis while it holds
                                           #   functions is skipped with a reason
reportal serve [--port 8002] [--host 127.0.0.1] [--no-open]
                                           # a non-loopback --host refuses to start
                                           #   unless token auth is on and a user exists
reportal mcp [--json]                      # run the stdio MCP server: newline-delimited
                                           #   JSON-RPC 2.0 on stdin/stdout (initialize,
                                           #   notifications/initialized, tools/list, tools/call)
reportal --version
```

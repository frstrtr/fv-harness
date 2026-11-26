# lib_classes.sh — sourced by the control scripts: the classification check every clean (PASS) control makes.
# classes_ok FUZZ_JSON: the edge-case classification ran over the whole corpus: a classes record, no
# classes.error (a classes.py that raises, a stopped replay or retention generation, a time guard), not
# skipped, and at least one class. A clean verdict alone does not show that the labels and retention ran.
classes_ok() {
  jq -e '(.classes | type == "object") and .classes.error == null and .classes.skipped == null
         and (.classes.classes | type == "array" and length > 0)' "$1" > /dev/null 2>&1
}
classes_why() { # classes_why FUZZ_JSON: one line for a WRONG message
  jq -r '"classes: " + (if (.classes | type) != "object" then "no record" elif .classes.error then "error " + (.classes.error | .[0:100])
         elif .classes.skipped then "skipped" else "\(.classes.classes | length) classes" end)' "$1" 2>/dev/null || echo "classes: no fuzz.json"
}
classes_skipped_by_design() { # classes_skipped_by_design FUZZ_JSON LANG: a language without classification says so
  jq -e --arg l "$2" '(.classes | type == "object") and .classes.error == null
         and (.classes.skipped // "" | contains("is not available for --lang " + $l))' "$1" > /dev/null 2>&1
}

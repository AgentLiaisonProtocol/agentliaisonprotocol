// Heading ids that match GitHub's, so links written for the repository keep working on the site.
// GitHub lower-cases the heading's text, drops every character that is not a letter, mark, digit,
// connector (such as "_"), hyphen or space, and turns each space into a hyphen. Repeats within one
// document get "-1", "-2", ... suffixes.

const DROP = /[^\p{L}\p{M}\p{N}\p{Pc}\- ]/gu;

/** The id GitHub gives a heading with this text (no repeat handling). */
export function slugify(text) {
  return String(text).toLowerCase().replace(DROP, "").replace(/ /g, "-");
}

/** Gives each heading of one document its id, adding -1, -2 ... for repeats, as GitHub does. */
export class Slugger {
  constructor() { this.seen = new Map(); }
  slug(text) {
    const base = slugify(text);
    let id = base;
    while (this.seen.has(id)) {
      const n = this.seen.get(base) + 1;
      this.seen.set(base, n);
      id = `${base}-${n}`;
    }
    this.seen.set(id, 0);
    return id;
  }
}

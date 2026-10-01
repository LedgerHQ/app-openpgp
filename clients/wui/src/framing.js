// Whether the page is displayed inside a frame of another page. A top window
// that cannot be compared counts as framed.
export function isFramed(win = window) {
  try {
    return win.top !== win.self;
  } catch (e) {
    return true;
  }
}

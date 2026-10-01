import { isFramed } from "./framing";

describe("isFramed", () => {
  test("a top level page is not framed", () => {
    const win = {};
    win.self = win;
    win.top = win;
    expect(isFramed(win)).toBe(false);
  });
  test("a page inside a frame is framed", () => {
    const win = {};
    win.self = win;
    win.top = {};
    expect(isFramed(win)).toBe(true);
  });
  test("a page whose top window cannot be read is framed", () => {
    const win = {};
    win.self = win;
    Object.defineProperty(win, "top", {
      get() {
        throw new Error("blocked");
      },
    });
    expect(isFramed(win)).toBe(true);
  });
});

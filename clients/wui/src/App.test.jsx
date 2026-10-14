import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import App from "./App.jsx";

// Keep the GpgManager the App creates, to signal a device disconnection
const managers = vi.hoisted(() => []);
vi.mock("./controller/GpgManager.js", async (importOriginal) => {
  const { default: GpgManager } = await importOriginal();
  return {
    default: class extends GpgManager {
      constructor() {
        super();
        managers.push(this);
      }
    },
  };
});

// FileReader whose reads only complete when the test calls finish()
class FakeReader {
  static instances = [];

  constructor() {
    this.aborted = false;
    FakeReader.instances.push(this);
  }

  readAsArrayBuffer(file) {
    this.file = file;
  }

  abort() {
    this.aborted = true;
  }

  async finish() {
    this.result = await this.file.arrayBuffer();
    await this.onload?.();
  }
}

const backupFile = (name) => new File([JSON.stringify({ version: 1, name })], name, { type: "application/json" });

// Select `file` in the hidden restore file input
function pick(container, file) {
  const input = container.querySelector('input[type="file"]');
  Object.defineProperty(input, "files", { value: [file], configurable: true });
  fireEvent.change(input);
}

describe("restore file", () => {
  beforeEach(() => {
    window.history.replaceState({}, "", "/?mock");
    FakeReader.instances = [];
    vi.stubGlobal("FileReader", FakeReader);
    // jsdom has no ResizeObserver, which the dialog components use
    vi.stubGlobal(
      "ResizeObserver",
      class {
        observe() {}
        unobserve() {}
        disconnect() {}
      }
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  test("shows the name and SHA-256 of the file to restore", async () => {
    const { container } = render(<App />);
    pick(container, backupFile("first.json"));
    await act(() => FakeReader.instances[0].finish());

    expect(await screen.findByText("first.json")).toBeTruthy();
    expect(screen.getByText(/^SHA-256 [0-9a-f]{64}$/)).toBeTruthy();
  });

  test("ignores another file and keeps the actions disabled while a file is read", async () => {
    const { container } = render(<App />);
    pick(container, backupFile("first.json"));
    pick(container, backupFile("second.json"));

    expect(FakeReader.instances.length).toBe(1);
    expect(screen.getByText("Backup").closest("button").disabled).toBe(true);

    await act(() => FakeReader.instances[0].finish());
    expect(await screen.findByText("first.json")).toBeTruthy();
    expect(screen.queryByText("second.json")).toBeNull();
  });

  test("drops a read that completes after a disconnection", async () => {
    const { container } = render(<App />);
    pick(container, backupFile("first.json"));
    const reader = FakeReader.instances[0];

    await act(async () => managers[0].onDisconnect());
    expect(reader.aborted).toBe(true);

    await act(() => reader.finish());
    expect(screen.queryByText("first.json")).toBeNull();
    expect(screen.queryByText(/^SHA-256/)).toBeNull();
  });
});

describe("restore slot lookup", () => {
  let resolveSlot;

  beforeEach(() => {
    window.history.replaceState({}, "", "/");
    FakeReader.instances = [];
    vi.stubGlobal("FileReader", FakeReader);
    vi.stubGlobal(
      "ResizeObserver",
      class {
        observe() {}
        unobserve() {}
        disconnect() {}
      }
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  // Render the App connected to a manager whose active slot lookup completes when the test calls resolveSlot()
  async function renderConnected() {
    const view = render(<App />);
    const manager = managers[managers.length - 1];
    manager.connect = async () => {};
    resolveSlot = undefined;
    manager.activeSlot = () => new Promise((resolve) => (resolveSlot = resolve));
    fireEvent.click(screen.getByText("Connect"));
    await screen.findByText("Backup");
    return { ...view, manager };
  }

  // Complete the file read, which then waits for the active slot
  async function readFile(container) {
    pick(container, backupFile("first.json"));
    act(() => {
      FakeReader.instances[0].finish();
    });
    await waitFor(() => expect(resolveSlot).toBeDefined());
  }

  test("keeps the actions disabled until the active slot is read", async () => {
    const { container } = await renderConnected();
    await readFile(container);

    expect(screen.getByText("Backup").closest("button").disabled).toBe(true);
    expect(screen.queryByText("first.json")).toBeNull();

    await act(async () => resolveSlot(1));
    expect(await screen.findByText("first.json")).toBeTruthy();
    expect(screen.getByText("Backup").closest("button").disabled).toBe(false);
  });

  test("does not open the restore dialog after a disconnection during the slot read", async () => {
    const { container, manager } = await renderConnected();
    await readFile(container);

    await act(async () => manager.onDisconnect());
    await act(async () => resolveSlot(1));
    expect(screen.queryByText("This overwrites the current card configuration.")).toBeNull();
  });
});

import { useEffect, useRef, useState } from "react";
import {
  ThemeProvider,
  TooltipProvider,
  Button,
  Banner,
  Checkbox,
  TextInput,
  Tag,
  Divider,
  Spinner,
  SegmentedControl,
  SegmentedControlButton,
  Dialog,
  DialogContent,
  DialogHeader,
  DialogBody,
  DialogFooter,
} from "@ledgerhq/lumen-ui-react";
import {
  CloudDownload,
  CloudUpload,
  Trash,
  Unlink,
  Usb,
  ShieldCheck,
  Warning,
  CheckmarkCircleFill,
} from "@ledgerhq/lumen-ui-react/symbols";
import { listen } from "@ledgerhq/logs";
import {
  decryptBackup,
  encryptBackup,
  isEncryptedBackup,
} from "./controller/backupFormat.js";
import GpgManager from "./controller/GpgManager.js";
import logo from "./logo.svg";

const gpg = new GpgManager();
if (import.meta.env.DEV) {
  listen((event) => {
    if (event?.type === "apdu") return;
    console.debug(event);
  });
}

async function saveJSON(payload, suggestedName) {
  const text = JSON.stringify(payload, null, 2);

  if (window.showSaveFilePicker) {
    let handle;
    try {
      handle = await window.showSaveFilePicker({
        suggestedName,
        types: [
          { description: "OpenPGP backup", accept: { "application/json": [".json"] } },
        ],
      });
    } catch (error) {
      if (error.name === "AbortError") return false;
      throw error;
    }
    const writable = await handle.createWritable();
    await writable.write(text);
    await writable.close();
    return true;
  }

  const blob = new Blob([text], { type: "application/json;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = suggestedName;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  return true;
}

async function saveBytes(bytes, suggestedName) {
  if (window.showSaveFilePicker) {
    let handle;
    try {
      handle = await window.showSaveFilePicker({
        suggestedName,
        types: [{ description: "OpenPGP backup", accept: { "application/octet-stream": [".json"] } }],
      });
    } catch (error) {
      if (error.name === "AbortError") return false;
      throw error;
    }
    const writable = await handle.createWritable();
    await writable.write(bytes);
    await writable.close();
    return true;
  }
  const blob = new Blob([bytes], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = suggestedName;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  return true;
}

const PIN_DIALOG = {
  backup: { title: "Backup", description: "Enter your PINs to read the card.", submit: "Backup", appearance: "accent", showUser: true, showRegen: false, showSlot: true, showFilePass: true },
  restore: { title: "Restore", description: "This overwrites the current card configuration.", submit: "Restore", appearance: "accent", showUser: true, showRegen: true, showSlot: true, showFilePass: true },
  factoryReset: { title: "Factory reset", description: "This erases all keys and resets the PINs to their defaults.", submit: "Erase", appearance: "red", showUser: false, showRegen: false, showSlot: false, showFilePass: false },
};

export default function App() {
  const mock =
    import.meta.env.DEV &&
    new URLSearchParams(window.location.search).has("mock");

  const [busy, setBusy] = useState(false);
  const [connected, setConnected] = useState(mock);
  const [aid, setAid] = useState(mock ? "D2760001240103032C97DEADBEEF0000" : null);
  const [serial, setSerial] = useState(mock ? "DEADBEEF" : null);
  const [pinAction, setPinAction] = useState(null);
  const [failures, setFailures] = useState(null);
  const [restartHint, setRestartHint] = useState(false);
  const [notice, setNotice] = useState(null);

  const [userPin, setUserPin] = useState("");
  const [adminPin, setAdminPin] = useState("");
  const [filePassphrase, setFilePassphrase] = useState("");
  const [isEncryptedFile, setIsEncryptedFile] = useState(false);
  const [regen, setRegen] = useState(true);
  const [slot, setSlot] = useState("1");

  const restoreContent = useRef(null);
  const fileInput = useRef(null);
  const regeneratingRef = useRef(false);

  useEffect(() => {
    gpg.onDisconnect = () => {
      const wasRegenerating = regeneratingRef.current;
      regeneratingRef.current = false;
      setConnected(false);
      setBusy(false);
      setAid(null);
      setSerial(null);
      // Close any open PIN dialog so the notice below is visible.
      setPinAction(null);
      setUserPin("");
      setAdminPin("");
      setSlot("1");
      setNotice(
        wasRegenerating
          ? {
              appearance: "warning",
              title: "The app crashed during key regeneration",
              description:
                "Known device-side issue. Your keys were most likely regenerated anyway — restart the OpenPGP app, reconnect and verify.",
            }
          : { appearance: "warning", title: "Device disconnected", description: "Reconnect to continue." }
      );
    };
    return () => {
      gpg.onDisconnect = null;
    };
  }, []);

  function closePin() {
    setPinAction(null);
    setUserPin("");
    setAdminPin("");
    setFilePassphrase("");
    setIsEncryptedFile(false);
    setSlot("1");
  }

  async function onConnect() {
    setBusy(true);
    setFailures(null);
    setRestartHint(false);
    try {
      await gpg.connect();
      setAid(gpg.aid);
      setSerial(gpg.serial);
      setConnected(true);
      setNotice({ appearance: "success", title: "Device connected" });
    } catch (error) {
      await gpg.disconnect();
      setConnected(false);
      setAid(null);
      setSerial(null);
      setNotice({ appearance: "error", title: "Connection failed", description: String(error) });
    } finally {
      setBusy(false);
    }
  }

  async function onDisconnect() {
    await gpg.disconnect();
    setConnected(false);
    setAid(null);
    setSerial(null);
    setFailures(null);
    setRestartHint(false);
    setNotice({ appearance: "info", title: "Disconnected" });
  }

  function onPickRestoreFile(event) {
    const file = event.target.files[0];
    event.target.value = "";
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      const bytes = new Uint8Array(reader.result);
      restoreContent.current = bytes;
      setIsEncryptedFile(isEncryptedBackup(bytes));
      setRegen(true);
      setPinAction("restore");
    };
    reader.readAsArrayBuffer(file);
  }

  async function submitPin(event) {
    event.preventDefault();
    setBusy(true);
    if (pinAction === "restore") regeneratingRef.current = regen;
    try {
      if (pinAction === "backup") {
        const payload = await gpg.backup(userPin, adminPin, parseInt(slot, 10) - 1);
        closePin();
        const name = `gpg_backup_${serial || "openpgp"}.json`;
        let saved;
        if (filePassphrase) {
          const encrypted = await encryptBackup(payload, filePassphrase);
          saved = await saveBytes(encrypted, name);
        } else {
          saved = await saveJSON(payload, name);
        }
        setNotice(
          saved
            ? { appearance: "success", title: "Backup saved" }
            : { appearance: "info", title: "Backup cancelled" }
        );
      } else if (pinAction === "restore") {
        const content = isEncryptedFile
          ? await decryptBackup(restoreContent.current, filePassphrase)
          : new TextDecoder().decode(restoreContent.current);
        const f = await gpg.restore(userPin, adminPin, content, regen, parseInt(slot, 10) - 1);
        closePin();
        restoreContent.current = null;
        setFailures(f);
        setRestartHint(true);
        setNotice(
          f.length === 0
            ? { appearance: "success", title: "Restore complete" }
            : { appearance: "warning", title: `Restore done — ${f.length} item(s) rejected (see below).` }
        );
      } else if (pinAction === "factoryReset") {
        await gpg.factoryReset(adminPin);
        await gpg.disconnect();
        setConnected(false);
        setAid(null);
        setSerial(null);
        setFailures(null);
        setRestartHint(true);
        closePin();
        setNotice({
          appearance: "success",
          title: "Card erased (PINs reset to default)",
          description: "Restart the app on your device, then reconnect.",
        });
      }
    } catch (error) {
      closePin();
      setNotice({ appearance: "error", title: "Operation failed", description: String(error) });
    } finally {
      setBusy(false);
      regeneratingRef.current = false;
    }
  }

  const cfg = pinAction ? PIN_DIALOG[pinAction] : null;
  const canSubmit =
    !busy &&
    (!cfg?.showUser || userPin.length > 0) &&
    adminPin.length > 0 &&
    !(pinAction === "restore" && isEncryptedFile && filePassphrase.length === 0);

  return (
    <ThemeProvider colorScheme="dark">
      <TooltipProvider>
        <div className="flex min-h-screen flex-col items-center bg-canvas px-16 py-32">
          {/* Header */}
          <div className="flex flex-col items-center gap-12 mb-32">
            <img src={logo} alt="" className="size-48" />
            <h1 className="heading-2-semi-bold text-base">OpenPGP Backup & Restore</h1>
            <p className="body-2 text-muted">
              Backup, restore or factory-reset your Ledger OpenPGP card.
            </p>
          </div>

          {/* Content area */}
          <div className="flex w-full max-w-480 flex-col gap-20">
            {/* Notice banner */}
            {notice && (
              <Banner
                appearance={notice.appearance}
                title={notice.title}
                description={notice.description}
                onClose={() => setNotice(null)}
              />
            )}

            {/* Connection card */}
            <div className="bg-base border border-base rounded-lg p-20">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-12">
                  <Usb size={20} className="text-muted" />
                  <span className="body-2-semi-bold text-base">Device</span>
                </div>
                {connected ? (
                  <Tag appearance="success" icon={CheckmarkCircleFill} label="Connected" />
                ) : (
                  <Tag appearance="gray" label="Not connected" />
                )}
              </div>

              {connected && (
                <>
                  <Divider className="my-16" />
                  <div className="flex flex-col gap-8">
                    <div className="flex items-center justify-between">
                      <span className="body-3 text-muted">AID</span>
                      <span className="body-3 text-base font-mono">{aid || "—"}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="body-3 text-muted">Serial</span>
                      <Tag appearance="gray" label={serial || "—"} />
                    </div>
                  </div>
                </>
              )}
            </div>

            {/* Actions card */}
            <div className="bg-base border border-base rounded-lg p-20">
              <div className="flex items-center gap-12 mb-16">
                <ShieldCheck size={20} className="text-muted" />
                <span className="body-2-semi-bold text-base">Actions</span>
              </div>
              <Divider className="mb-16" />

              {!connected && (
                <div className="flex flex-col items-center gap-16 py-24">
                  {busy ? (
                    <Spinner size={32} />
                  ) : (
                    <>
                      <p className="body-2 text-muted">Connect your Ledger with the OpenPGP app open.</p>
                      <Button appearance="accent" icon={Usb} disabled={busy} loading={busy} onClick={onConnect}>
                        Connect
                      </Button>
                    </>
                  )}
                </div>
              )}

              {connected && (
                <div className="flex flex-col gap-10">
                  <Button appearance="accent" icon={CloudDownload} disabled={busy} onClick={() => setPinAction("backup")}>
                    Backup
                  </Button>
                  <Button appearance="base" icon={CloudUpload} disabled={busy} onClick={() => fileInput.current.click()}>
                    Restore
                  </Button>
                  <Divider className="my-6" />
                  <Button appearance="red" icon={Trash} disabled={busy} onClick={() => setPinAction("factoryReset")}>
                    Factory reset
                  </Button>
                  <Button appearance="gray" icon={Unlink} disabled={busy} onClick={onDisconnect}>
                    Disconnect
                  </Button>
                </div>
              )}

              <input
                ref={fileInput}
                type="file"
                accept=".json,application/json"
                className="hidden"
                onChange={onPickRestoreFile}
              />
            </div>

            {/* Info banner */}
            {connected && (
              <Banner
                appearance="info"
                title="Keep your backup safe"
                description="The backup file holds encrypted key material. Restoring the keys requires the app's SEED mode."
              />
            )}

            {/* Failures */}
            {failures && failures.length > 0 && (
              <div className="bg-base border border-base rounded-lg p-20">
                <div className="flex items-center gap-12 mb-12">
                  <Warning size={20} className="text-warning" />
                  <span className="body-2-semi-bold text-warning">
                    {failures.length} item(s) rejected by the card
                  </span>
                </div>
                <Divider className="mb-12" />
                <div className="flex flex-col gap-6">
                  {failures.map((f, i) => (
                    <div key={i} className="flex items-start gap-8">
                      <span className="body-3 text-muted shrink-0">•</span>
                      <span className="body-3 text-muted">
                        {f.name} — {f.message}
                      </span>
                    </div>
                  ))}
                </div>
                <p className="body-3 text-muted mt-12">
                  If key regeneration failed, enable SEED mode on the device (Settings → Seed Mode) and
                  restore onto a device with the same recovery phrase.
                </p>
              </div>
            )}

            {/* Restart hint */}
            {restartHint && (
              <Banner
                appearance="info"
                title="Restart the OpenPGP app"
                description="The card state changed. Restart the app on your device and reload scdaemon (gpgconf --kill scdaemon) so gpg picks up the new state."
              />
            )}
          </div>

          {/* Footer */}
          <div className="mt-auto pt-40 text-center">
            <p className="body-3 text-muted">Requires a Chromium-based browser with WebHID.</p>
            <p className="body-4 text-muted-subtle mt-4">
              Close gpg / scdaemon before and after operations.
            </p>
          </div>
        </div>

        {/* PIN Dialog */}
        <Dialog open={pinAction !== null} onOpenChange={(open) => !open && closePin()}>
          <DialogContent>
            <DialogHeader title={cfg?.title} description={cfg?.description} onClose={closePin} />
            <DialogBody>
              {busy && (
                <div className="flex flex-col items-center gap-12 py-24 text-center">
                  <Spinner />
                  <p className="body-2 text-muted">
                    Working…
                    {cfg?.showRegen && regen
                      ? " Regenerating keys can take a while."
                      : ""}{" "}
                    If it stalls, restart the OpenPGP app on the device.
                  </p>
                </div>
              )}
              <form
                id="pin-form"
                onSubmit={submitPin}
                className={busy ? "hidden" : "flex flex-col gap-16"}
              >
                {cfg?.showSlot && (
                  <div className="flex flex-col gap-8">
                    <span className="body-3-semi-bold text-base">Key slot</span>
                    <SegmentedControl
                      selectedValue={slot}
                      onSelectedChange={setSlot}
                      disabled={busy}
                    >
                      <SegmentedControlButton value="1">Slot 1</SegmentedControlButton>
                      <SegmentedControlButton value="2">Slot 2</SegmentedControlButton>
                      <SegmentedControlButton value="3">Slot 3</SegmentedControlButton>
                    </SegmentedControl>
                  </div>
                )}
                {cfg?.showUser && (
                  <TextInput
                    label="User PIN"
                    type="password"
                    inputMode="numeric"
                    autoComplete="off"
                    hideClearButton
                    value={userPin}
                    disabled={busy}
                    onChange={(e) => setUserPin(e.target.value)}
                  />
                )}
                <TextInput
                  label="Admin PIN"
                  type="password"
                  inputMode="numeric"
                  autoComplete="off"
                  hideClearButton
                  value={adminPin}
                  disabled={busy}
                  onChange={(e) => setAdminPin(e.target.value)}
                />
                {cfg?.showFilePass && (
                  <TextInput
                    label={
                      pinAction === "restore" && isEncryptedFile
                        ? "File passphrase (file is encrypted — required)"
                        : "File passphrase (optional — encrypts the backup file)"
                    }
                    type="password"
                    autoComplete="off"
                    hideClearButton
                    value={filePassphrase}
                    disabled={busy}
                    onChange={(e) => setFilePassphrase(e.target.value)}
                  />
                )}
                {cfg?.showRegen && (
                  <label className="flex cursor-pointer items-start gap-12">
                    <Checkbox
                      checked={regen}
                      disabled={busy}
                      onCheckedChange={setRegen}
                      className="mt-2 shrink-0"
                    />
                    <span className="body-3 text-base">
                      Regenerate keys from the device seed
                      <span className="block body-4 text-muted mt-2">
                        Requires SEED mode; may take a while.
                      </span>
                    </span>
                  </label>
                )}
              </form>
            </DialogBody>
            <DialogFooter>
              <Button appearance="gray" disabled={busy} onClick={closePin}>
                Cancel
              </Button>
              <Button
                type="submit"
                form="pin-form"
                appearance={cfg?.appearance}
                loading={busy}
                disabled={!canSubmit}
              >
                {cfg?.submit}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </TooltipProvider>
    </ThemeProvider>
  );
}

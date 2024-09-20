# The MIT License (MIT)

# Copyright (c) 2021-2024 Krux contributors

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

from embit import bip32, compact
import hashlib
import binascii
from .. import MENU_CONTINUE, LOAD_FROM_CAMERA, LOAD_FROM_SD, Menu
from ..utils import Utils
from ...key import SINGLESIG_SCRIPT_PURPOSE
from ...themes import theme
from ...display import (
    DEFAULT_PADDING,
    MINIMAL_DISPLAY,
    FONT_HEIGHT,
    TOTAL_LINES,
    BOTTOM_PROMPT_LINE,
)
from ...baseconv import base_encode
from ...krux_settings import t
from ...qr import FORMAT_NONE
from ...sd_card import (
    SIGNATURE_FILE_EXTENSION,
    SIGNED_FILE_SUFFIX,
    PUBKEY_FILE_EXTENSION,
)


class SignMessage(Utils):
    """Message Signing user interface"""

    def _load_message(self):
        """Loads a message from camera or SD card"""
        load_method = self.load_method()

        if load_method == LOAD_FROM_CAMERA:
            from ..qr_capture import QRCodeCapture

            qr_capture = QRCodeCapture(self.ctx)
            data, qr_format = qr_capture.qr_capture_loop()
            return (data, qr_format, "")
        if load_method == LOAD_FROM_SD:
            message_filename, data = self.load_file(prompt=False)
            return (data, FORMAT_NONE, message_filename)
        return (None, None, "")

    def _is_valid_derivation_path(self, derivation_path):
        """Checks if the derivation path is valid"""
        try:
            parts = derivation_path.split("/")
            return parts[0] == "m" and all(
                p.endswith("'") or p.endswith("h") or p.isdigit() for p in parts[1:]
            )
        except:
            return False

    def _sign_at_address(self, message, derivation_str):
        """Signs a message at a derived Bitcoin address"""
        derivation = bip32.parse_path(derivation_str)
        wallet_path = "/".join(derivation_str.split("/")[:4])

        if wallet_path == self.ctx.wallet.key.derivation:
            # Show derived address
            address = self.ctx.wallet.descriptor.derive(
                derivation[4], branch_index=0
            ).address(network=self.ctx.wallet.key.network)
            address_derivation = self.fit_to_line(
                address, str(derivation[4]) + ". ", fixed_chars=3
            )
        else:
            address_derivation = derivation_str.replace("h", "'")

        self._display_message_sign_prompt(message, address_derivation)

        if not self.prompt(t("Sign?"), BOTTOM_PROMPT_LINE):
            return None

        message_hash = hashlib.sha256(
            hashlib.sha256(
                b"\x18Bitcoin Signed Message:\n"
                + compact.to_bytes(len(message))
                + message
            ).digest()
        ).digest()

        sig = self.ctx.wallet.key.sign_at(derivation, message_hash)
        self._display_signature(base_encode(sig, 64).strip().decode())
        return sig

    def _display_message_sign_prompt(self, message, address_derivation):
        """Helper to display message and address for signing"""
        max_lines = TOTAL_LINES - (7 if MINIMAL_DISPLAY else 10)
        offset_y = DEFAULT_PADDING
        self.ctx.display.clear()

        offset_y += (
            self.ctx.display.draw_hcentered_text(
                t("Message:"), offset_y, theme.highlight_color
            )
            * FONT_HEIGHT
        )
        offset_y += (
            self.ctx.display.draw_hcentered_text(
                message.decode(), offset_y, max_lines=max_lines
            )
            + 1
        ) * FONT_HEIGHT
        offset_y += (
            self.ctx.display.draw_hcentered_text(
                t("Address") + ":", offset_y, theme.highlight_color
            )
            * FONT_HEIGHT
        )
        self.ctx.display.draw_hcentered_text(address_derivation, offset_y)

    def _display_signature(self, encoded_sig):
        """Helper to display the signature"""
        self.ctx.display.clear()
        self.ctx.display.draw_centered_text(t("Signature") + ":\n\n%s" % encoded_sig)
        self.ctx.input.wait_for_button()

    def _sign_at_address_from_qr(self, data):
        """Message signed at a derived Bitcoin address - Sparrow/Specter"""
        if not data.startswith(b"signmessage"):
            return None

        data_blocks = data.split(b" ")
        derivation = data_blocks[1].decode()
        if len(data_blocks) < 3 or not self._is_valid_derivation_path(derivation):
            return None

        message = b" ".join(data_blocks[2:]).split(b":", 1)
        if len(message) < 2 or message[0] != b"ascii":
            return None

        return self._sign_at_address(b" ".join(message[1:]), derivation)

    def _sign_at_address_from_sd(self, data):
        """Message signed at a derived Bitcoin address - SD card"""
        data = data.decode() if isinstance(data, bytes) else data
        lines = [line.strip() for line in data.splitlines() if line.strip()]
        if len(lines) < 2 or lines[-1].lower() not in SINGLESIG_SCRIPT_PURPOSE:
            return None
        derivation_path = lines[-2]
        if not self._is_valid_derivation_path(derivation_path):
            return None
        message = "\n".join(lines[:-2])

        return self._sign_at_address(message.encode(), derivation_path)

    def sign_standard_message(self, data):
        """Signs a standard message"""
        message_hash = self._compute_message_hash(data)
        if message_hash is None:
            return ""

        self.ctx.display.clear()
        self.ctx.display.draw_centered_text(
            "SHA256:\n%s" % binascii.hexlify(message_hash).decode()
        )
        if not self.prompt(t("Sign?"), BOTTOM_PROMPT_LINE):
            return ""

        sig = self.ctx.wallet.key.sign(message_hash).serialize()
        self._display_signature(base_encode(sig, 64).strip().decode())
        return sig

    def _compute_message_hash(self, data):
        """Computes the hash for the message"""
        if len(data) == 32:
            return data
        if len(data) == 64:
            try:
                return binascii.unhexlify(data)
            except:
                pass
        return hashlib.sha256(data).digest()

    def _export_signature(
        self, sig, qr_format=FORMAT_NONE, sign_at_address=False, message_filename=""
    ):
        """Exports the message signature to a QR code or SD card"""
        sign_menu = Menu(
            self.ctx,
            [
                (t("Sign to QR code"), lambda: None),
                (
                    t("Sign to SD card"),
                    None if not self.has_sd_card() else lambda: None,
                ),
            ],
            back_status=lambda: None,
        )
        index, _ = sign_menu.run_loop()

        if index == 2:
            return MENU_CONTINUE

        pubkey = binascii.hexlify(self.ctx.wallet.key.account.sec()).decode()

        if index == 0:
            self._export_to_qr(sig, pubkey, qr_format, sign_at_address)
        elif self.has_sd_card():
            self._export_to_sd(sig, pubkey, sign_at_address, message_filename)
        return MENU_CONTINUE

    def _export_to_qr(self, sig, pubkey, qr_format, sign_at_address):
        """Exports the signature and public key to QR code"""
        encoded_sig = base_encode(sig, 64).strip().decode()
        title = t("Signed Message")
        self.display_qr_codes(encoded_sig, qr_format, title)
        self.print_standard_qr(encoded_sig, qr_format, title)

        if not sign_at_address:
            self._display_and_export_pubkey(pubkey, qr_format)

    def _display_and_export_pubkey(self, pubkey, qr_format):
        """Displays and exports the public key as QR code"""
        title = t("Hex Public Key")
        self.ctx.display.clear()
        self.ctx.display.draw_centered_text(title + ":\n\n%s" % pubkey)
        self.ctx.input.wait_for_button()

        self.display_qr_codes(pubkey, qr_format, title)
        self.print_standard_qr(pubkey, qr_format, title)

    def _export_to_sd(self, sig, pubkey, sign_at_address, message_filename):
        """Exports the signature and public key to SD card"""
        from ..file_operations import SaveFile

        save_page = SaveFile(self.ctx)
        sig = base_encode(sig, 64).strip().decode()
        extension = ".txt" if sign_at_address else SIGNATURE_FILE_EXTENSION
        save_page.save_file(
            sig,
            "message",
            message_filename,
            t("Signature") + ":",
            extension,
            SIGNED_FILE_SUFFIX,
            prompt=False,
        )

        if not sign_at_address:
            title = t("Hex Public Key")
            save_page.save_file(
                pubkey, "pubkey", "", title + ":", PUBKEY_FILE_EXTENSION, "", False
            )

    def sign_message(self):
        """Sign message user interface"""
        data, qr_format, message_filename = self._load_message()

        if data is None:
            self.flash_error(t("Failed to load message"))
            return MENU_CONTINUE

        if message_filename:
            sig = self._sign_at_address_from_sd(data)
            if sig:
                self._export_signature(sig, FORMAT_NONE, True, message_filename)
                return MENU_CONTINUE

        data = data.encode() if isinstance(data, str) else data
        sig = self._sign_at_address_from_qr(data)
        if sig:
            self._export_signature(sig, qr_format, True, message_filename)
            return MENU_CONTINUE
        sig = self.sign_standard_message(data)
        if sig:
            self._export_signature(sig, qr_format, False, message_filename)
        return MENU_CONTINUE

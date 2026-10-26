"""LinkProof QR Code Generation and Decoding Service.

Generates QR codes carrying canonical LinkProof signed records, and
decodes QR codes from image uploads using OpenCV and adaptive image enhancement.
"""
from __future__ import annotations

import base64
import io
import json
from typing import Any, Dict, Optional, Tuple, Union

import cv2
import numpy as np
import qrcode
from PIL import Image


def generate_qr_image_bytes(
    payload: Union[Dict[str, Any], str],
    image_format: str = "PNG",
    box_size: int = 8,
    border: int = 4,
) -> bytes:
    """Generate a high-contrast QR code image from payload data.

    Returns the raw image bytes in the specified format (default PNG).
    """
    if isinstance(payload, dict):
        # Compact serialization without whitespace
        text_data = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    else:
        text_data = str(payload)

    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=box_size,
        border=border,
    )
    qr.add_data(text_data)
    qr.make(fit=True)

    img = qr.make_image(fill_color="#0F172A", back_color="#FFFFFF")
    buffer = io.BytesIO()
    img.save(buffer, format=image_format)
    return buffer.getvalue()


def generate_qr_data_uri(
    payload: Union[Dict[str, Any], str],
    image_format: str = "PNG",
) -> str:
    """Generate a Base64 data URI for directly rendering a QR image in HTML."""
    img_bytes = generate_qr_image_bytes(payload, image_format=image_format)
    b64_str = base64.b64encode(img_bytes).decode("ascii")
    return f"data:image/{image_format.lower()};base64,{b64_str}"


def decode_qr_image_bytes(
    image_bytes: bytes,
) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]], str]:
    """Decode a QR code from image bytes using OpenCV with multi-pass image enhancement.

    Returns (success, raw_text, parsed_json_or_none, message).
    """
    if not image_bytes or len(image_bytes) < 16:
        return False, None, None, "Uploaded file is empty or corrupted."

    try:
        np_arr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
        if img is None:
            return False, None, None, "Could not decode uploaded image. Unsupported or corrupted image format."
    except Exception as e:
        return False, None, None, f"Image decoding error: {str(e)}"

    detectors = []
    if hasattr(cv2, "QRCodeDetectorAruco"):
        try:
            detectors.append(cv2.QRCodeDetectorAruco())
        except Exception:
            pass
    detectors.append(cv2.QRCodeDetector())

    def _try_detect(image_mat) -> Optional[str]:
        for det in detectors:
            try:
                res, _, _ = det.detectAndDecode(image_mat)
                if res and res.strip():
                    return res.strip()
            except Exception:
                pass
        return None

    # Pass 1: Original image
    txt = _try_detect(img)
    if txt:
        return _parse_decoded_content(txt)

    # Pass 2: Grayscale
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    txt = _try_detect(gray)
    if txt:
        return _parse_decoded_content(txt)

    # Pass 2.5: White border padding (provides clean quiet-zone for OpenCV)
    padded = cv2.copyMakeBorder(gray, 30, 30, 30, 30, cv2.BORDER_CONSTANT, value=255)
    decoded_text, _, _ = detector.detectAndDecode(padded)
    if decoded_text and decoded_text.strip():
        return _parse_decoded_content(decoded_text.strip())

    # Pass 3: Otsu Thresholding
    _, thresh_otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    decoded_text, _, _ = detector.detectAndDecode(thresh_otsu)
    if decoded_text and decoded_text.strip():
        return _parse_decoded_content(decoded_text.strip())

    # Pass 4: Adaptive Thresholding
    thresh_adapt = cv2.adaptiveThreshold(
        gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 51, 10
    )
    decoded_text, _, _ = detector.detectAndDecode(thresh_adapt)
    if decoded_text and decoded_text.strip():
        return _parse_decoded_content(decoded_text.strip())

    # Pass 5: Resize (downscale if huge, upscale if small)
    h, w = gray.shape[:2]
    if max(h, w) > 1600:
        scale = 1600.0 / max(h, w)
        resized = cv2.resize(gray, (int(w * scale), int(h * scale)), interpolation=cv2.INTER_AREA)
        decoded_text, _, _ = detector.detectAndDecode(resized)
        if decoded_text and decoded_text.strip():
            return _parse_decoded_content(decoded_text.strip())
    elif min(h, w) < 300:
        resized = cv2.resize(gray, (w * 2, h * 2), interpolation=cv2.INTER_CUBIC)
        decoded_text, _, _ = detector.detectAndDecode(resized)
        if decoded_text and decoded_text.strip():
            return _parse_decoded_content(decoded_text.strip())

    return False, None, None, "No QR code could be detected in the provided image."


def _parse_decoded_content(
    text: str,
) -> Tuple[bool, str, Optional[Dict[str, Any]], str]:
    """Parse decoded QR content as JSON if applicable, or return raw text."""
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return True, text, data, "Successfully decoded LinkProof JSON payload from QR code."
    except Exception:
        pass
    return True, text, None, "Successfully decoded raw text/URL from QR code."

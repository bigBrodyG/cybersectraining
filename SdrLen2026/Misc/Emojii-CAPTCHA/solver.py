import base64
import os
import socket
import time
from typing import List, Optional, Tuple

import cv2
import numpy as np


HOST = "emoji.challs.srdnlen.it"
PORT = 1717
TOP_K = 8
ANGLES = list(range(0, 360, 4))


def nonwhite_alpha_from_bgr(bgr: np.ndarray, thr: int = 248) -> np.ndarray:
    gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)
    alpha = (gray < thr).astype(np.uint8) * 255
    kernel = np.ones((3, 3), dtype=np.uint8)
    alpha = cv2.morphologyEx(alpha, cv2.MORPH_OPEN, kernel)
    return alpha


def to_black_bg(bgr: np.ndarray, alpha: np.ndarray) -> np.ndarray:
    out = bgr.copy()
    out[alpha == 0] = (0, 0, 0)
    return out


def extract_histogram(img: np.ndarray) -> np.ndarray:
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    _, thresh = cv2.threshold(gray, 250, 255, cv2.THRESH_BINARY_INV)
    contours, _ = cv2.findContours(thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    if not contours:
        return np.zeros((16**3,), dtype=np.float32)

    x_min = min(cv2.boundingRect(c)[0] for c in contours)
    y_min = min(cv2.boundingRect(c)[1] for c in contours)
    x_max = max(cv2.boundingRect(c)[0] + cv2.boundingRect(c)[2] for c in contours)
    y_max = max(cv2.boundingRect(c)[1] + cv2.boundingRect(c)[3] for c in contours)

    roi_bgr = img[y_min:y_max, x_min:x_max]
    roi_gray = gray[y_min:y_max, x_min:x_max]
    _, roi_alpha = cv2.threshold(roi_gray, 250, 255, cv2.THRESH_BINARY_INV)

    hsv = cv2.cvtColor(roi_bgr, cv2.COLOR_BGR2HSV)
    hist = cv2.calcHist([hsv], [0, 1, 2], roi_alpha, [16, 16, 16], [0, 180, 0, 256, 0, 256])
    hist = cv2.normalize(hist, hist, alpha=0, beta=1, norm_type=cv2.NORM_MINMAX)
    return hist.flatten().astype(np.float32)


def load_template_and_mask(png_path: str) -> Tuple[Optional[np.ndarray], Optional[np.ndarray]]:
    src = cv2.imread(png_path, cv2.IMREAD_UNCHANGED)
    if src is None:
        return None, None
    if src.ndim == 3 and src.shape[2] == 4:
        bgr = src[:, :, :3]
        alpha = src[:, :, 3]
    else:
        bgr = src[:, :, :3]
        alpha = nonwhite_alpha_from_bgr(bgr)
    black = to_black_bg(bgr, alpha)
    tmpl = cv2.resize(black, (80, 80), interpolation=cv2.INTER_AREA)
    mask = cv2.resize(alpha, (80, 80), interpolation=cv2.INTER_AREA)
    mask = (mask > 8).astype(np.uint8) * 255
    return tmpl, mask


def build_template_bank(dataset_keys: List[str]) -> Tuple[np.ndarray, np.ndarray]:
    tmpls = []
    masks = []
    for key in dataset_keys:
        png_path = os.path.join("emoji-data", "img-apple-160", f"{key}.png")
        tmpl, mask = load_template_and_mask(png_path)
        if tmpl is None or mask is None:
            tmpl = np.zeros((80, 80, 3), dtype=np.uint8)
            mask = np.zeros((80, 80), dtype=np.uint8)
        tmpls.append(tmpl)
        masks.append(mask)
    return np.stack(tmpls, axis=0), np.stack(masks, axis=0)


def rotate_tile_bank(tile: np.ndarray) -> List[np.ndarray]:
    t128 = cv2.resize(tile, (128, 128), interpolation=cv2.INTER_AREA)
    center = (64, 64)
    bank = []
    for angle in ANGLES:
        matrix = cv2.getRotationMatrix2D(center, angle, 1.0)
        rot = cv2.warpAffine(t128, matrix, (128, 128), borderValue=(0, 0, 0))
        bank.append(rot)
    return bank


def split_tiles(img: np.ndarray) -> List[np.ndarray]:
    return [
        img[0:256, 0:256],
        img[0:256, 256:512],
        img[0:256, 512:768],
        img[0:256, 768:1024],
        img[256:512, 0:256],
        img[256:512, 256:512],
        img[256:512, 512:768],
        img[256:512, 768:1024],
    ]


def solve_image(
    img_path: str,
    dataset_hist: dict,
    dataset_keys: List[str],
    key_to_idx: dict,
    tmpl_bank: np.ndarray,
    mask_bank: np.ndarray,
) -> str:
    img = cv2.imread(img_path)
    if img is None:
        raise RuntimeError(f"Cannot load {img_path}")

    tiles = split_tiles(img)
    answer = []

    for tile in tiles:
        tile_hist = extract_histogram(tile)

        scores = []
        for key in dataset_keys:
            ref = dataset_hist[key]
            dist = cv2.compareHist(tile_hist, ref, cv2.HISTCMP_BHATTACHARYYA)
            scores.append((dist, key))

        scores.sort(key=lambda x: x[0])

        if len(scores) > 1 and (scores[1][0] - scores[0][0]) > 0.15:
            answer.append(scores[0][1])
            continue

        top_candidates = [item[1] for item in scores[:TOP_K]]

        gray = cv2.cvtColor(tile, cv2.COLOR_BGR2GRAY)
        _, alpha = cv2.threshold(gray, 250, 255, cv2.THRESH_BINARY_INV)
        tile_black = tile.copy()
        tile_black[alpha == 0] = (0, 0, 0)

        rot_bank = rotate_tile_bank(tile_black)

        best_key = top_candidates[0]
        best_score = 999.0

        for key in top_candidates:
            idx = key_to_idx[key]
            cand80 = tmpl_bank[idx]
            cand_mask = mask_bank[idx]
            if int(np.count_nonzero(cand_mask)) < 20:
                continue

            for rot in rot_bank:
                val = float(np.min(cv2.matchTemplate(rot, cand80, cv2.TM_SQDIFF_NORMED, mask=cand_mask)))
                if val < best_score:
                    best_score = val
                    best_key = key

        answer.append(best_key)

    return " ".join(item.upper() for item in answer)


class BufferedSocket:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buf = b""

    def recv_until(self, marker: bytes, timeout: float = 10.0) -> str:
        self.sock.settimeout(timeout)
        while marker not in self.buf:
            chunk = self.sock.recv(8192)
            if not chunk:
                raise ConnectionError("Connection closed")
            self.buf += chunk
        idx = self.buf.index(marker) + len(marker)
        out = self.buf[:idx]
        self.buf = self.buf[idx:]
        return out.decode(errors="ignore")

    def recv_line(self, timeout: float = 10.0) -> str:
        self.sock.settimeout(timeout)
        while b"\n" not in self.buf:
            chunk = self.sock.recv(8192)
            if not chunk:
                raise ConnectionError("Connection closed")
            self.buf += chunk
        idx = self.buf.index(b"\n") + 1
        out = self.buf[:idx]
        self.buf = self.buf[idx:]
        return out.decode(errors="ignore")

    def read_available(self, timeout: float = 1.2) -> str:
        self.sock.settimeout(timeout)
        try:
            while True:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                self.buf += chunk
                if len(chunk) < 4096:
                    break
        except socket.timeout:
            pass
        out = self.buf.decode(errors="ignore")
        self.buf = b""
        return out


def run_remote(
    dataset_hist: dict,
    dataset_keys: List[str],
    key_to_idx: dict,
    tmpl_bank: np.ndarray,
    mask_bank: np.ndarray,
) -> None:
    sock = socket.create_connection((HOST, PORT), timeout=12)
    stream = BufferedSocket(sock)

    banner = stream.recv_until(b"> ", timeout=12)
    print(banner, end="")
    sock.sendall(b"2\n")
    print("[+] Challenge started")

    for ridx in range(1, 101):
        header = stream.recv_until(b"Here is your CAPTCHA:\n", timeout=12)
        if "srdnlen{" in header:
            print(header)
            return

        b64_line = ""
        while not b64_line:
            b64_line = stream.recv_line(timeout=8).strip()

        payload = base64.b64decode(b64_line)
        with open("current.png", "wb") as out:
            out.write(payload)

        t0 = time.time()
        ans = solve_image("current.png", dataset_hist, dataset_keys, key_to_idx, tmpl_bank, mask_bank)
        dt = time.time() - t0
        print(f"[*] Round {ridx}/100 solved in {dt:.3f}s")
        print(f"    --> {ans}")

        sock.sendall((ans + "\n").encode())
        resp = stream.read_available(timeout=1.2)
        if resp:
            print(resp.strip())

        if "srdnlen{" in resp:
            print("\n[!] FLAG FOUND")
            print(resp)
            return
        if "Wrong" in resp or "Timeout" in resp:
            raise RuntimeError(f"Failed at round {ridx}")


def main() -> None:
    dataset_hist = np.load("emoji_hist_dataset.npy", allow_pickle=True).item()
    dataset_keys = list(dataset_hist.keys())
    key_to_idx = {key: idx for idx, key in enumerate(dataset_keys)}
    tmpl_bank, mask_bank = build_template_bank(dataset_keys)
    run_remote(dataset_hist, dataset_keys, key_to_idx, tmpl_bank, mask_bank)


if __name__ == "__main__":
    main()

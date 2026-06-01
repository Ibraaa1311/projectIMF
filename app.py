import hashlib
import re
import time

import cv2
import matplotlib.pyplot as plt
import numpy as np
import streamlit as st

from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from skimage.metrics import mean_squared_error as mse_metric
from skimage.metrics import peak_signal_noise_ratio as psnr_metric
from skimage.metrics import structural_similarity as ssim_metric

# =========================
# UTILITIES FUNCTIONS
# =========================
# Mengubah text menjadi biner
def message_to_binary(message):
    return ''.join(format(ord(char), '08b') for char in message)

# Mengubah biner kembali menjadi text
def binary_to_message(binary):
    chars = []
    for i in range(0, len(binary) - len(binary) % 8, 8):
        chars.append(chr(int(binary[i:i + 8], 2)))
    return "".join(chars)

# Memuat gambar menggunakan OpenCV
def load_image(file_bytes):
    img = cv2.imdecode(np.frombuffer(file_bytes, np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError("Gambar tidak valid atau format tidak didukung.")
    return img

# Membentuk format pesan misi yang akan disisipkan
def format_mission_text(
    target,
    location,
    mission,
    self_destruct=False,
    timer=None
):
    prefix = f"[SD:{timer}]\n" if self_destruct else ""
    return f"""{prefix}Target   : {target}
Location : {location}
Mission  : {mission}
"""

# Validasi key untuk Random LSB
def is_random_key_valid(method, key):
    return method != "Random LSB" or bool(key and key.strip())

# =========================
# STEGANOGRAPHY FUNCTIONS
# =========================
# Menghitung kapasitas maksimum pesan berdasarkan m-bit dan ukuran gambar
def calculate_message_capacity(image, bit_depth):
    return max(((image.size * bit_depth) - 16) // 8, 0)

# Menyisipkan pesan ke dalam gambar
def embed_message_in_image(image, message, method, bit_depth=1, key=None):
    flat_pixels = image.flatten()
    binary_message = message_to_binary(message) + '1111111111111110'
    indices = np.arange(len(flat_pixels))

    if method == "Random LSB":
        seed = int(hashlib.sha256(key.encode()).hexdigest(), 16) % (2**32)
        np.random.seed(seed)
        np.random.shuffle(indices)

    mask = 0xFF ^ ((1 << bit_depth) - 1)
    for bit_offset, pixel_index in enumerate(indices):
        bit_start = bit_offset * bit_depth
        if bit_start >= len(binary_message):
            break
        chunk = binary_message[bit_start:bit_start + bit_depth].ljust(bit_depth, '0')
        flat_pixels[pixel_index] = (int(flat_pixels[pixel_index]) & mask) | int(chunk, 2)

    return flat_pixels.reshape(image.shape)

# Mengekstrak pesan dari gambar
def extract_message_from_image(image, method, bit_depth=1, key=None):
    flat_pixels = image.flatten()
    indices = np.arange(len(flat_pixels))

    if method == "Random LSB":
        seed = int(hashlib.sha256(key.encode()).hexdigest(), 16) % (2**32)
        np.random.seed(seed)
        np.random.shuffle(indices)

    terminator = "1111111111111110"
    bits = []
    tail = ""
    tail_limit = len(terminator) + bit_depth - 1

    for pixel_index in indices:
        chunk = format(flat_pixels[pixel_index], '08b')[-bit_depth:]
        bits.append(chunk)
        tail = (tail + chunk)[-tail_limit:]

        if terminator in tail:
            binary = "".join(bits)
            marker_pos = binary.find(terminator)
            return binary_to_message(binary[:marker_pos])

    return ""

# Generate hash gambar
def calculate_image_hash(file_bytes):
    return hashlib.md5(file_bytes).hexdigest()

# =========================
# ANALYSIS FUNCTIONS
# =========================
# Membuat error map
def create_error_map(original_image, stego_image):
    difference = cv2.absdiff(original_image, stego_image)
    grayscale_difference = cv2.cvtColor(difference, cv2.COLOR_BGR2GRAY)
    return cv2.threshold(grayscale_difference, 0, 255, cv2.THRESH_BINARY)[1]

# Membuat bit-plane image
def create_bit_planes(image):
    gray_image = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    return [((gray_image >> bit_index) & 1) * 255 for bit_index in range(8)]

# Badge HTML untuk menilai kualitas gambar berdasarkan metrik steganografi
def create_rating_badge(label, css_class):
    return f"<div class='rating-badge {css_class}'>{label}</div>"

# Menentukan rating berdasarkan nilai PSNR
def get_psnr_rating_badge(value):
    if value > 50:
        return create_rating_badge("EXCELLENT", "rating-excellent")
    if value > 30:
        return create_rating_badge("GOOD", "rating-good")
    return create_rating_badge("POOR", "rating-poor")

# Menentukan rating berdasarkan nilai MSE
def get_mse_rating_badge(value):
    if value < 1:
        return create_rating_badge("EXCELLENT", "rating-excellent")
    if value < 10:
        return create_rating_badge("GOOD", "rating-good")
    return create_rating_badge("POOR", "rating-poor")

# Menentukan rating berdasarkan nilai SSIM
def get_ssim_rating_badge(value):
    if value > 0.98:
        return create_rating_badge("EXCELLENT", "rating-excellent")
    if value > 0.90:
        return create_rating_badge("GOOD", "rating-good")
    return create_rating_badge("POOR", "rating-poor")

# =========================
# CRYPTOGRAPHY FUNCTIONS
# =========================
# Enkripsi Caesar Cipher
def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char)-base+shift)%26+base)
        else:
            result += char
    return result

# Dekripsi Caesar Cipher
def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

# Enkripsi Vigenere Cipher
def vigenere_encrypt(text, key):
    try:
        result = ""
        key = key.lower()
        key_index = 0
        for char in text:
            if char.isalpha():
                shift = ord(key[key_index % len(key)])-97
                base = ord('A') if char.isupper() else ord('a')
                result += chr((ord(char)-base+shift)%26+base)
                key_index += 1
            else:
                result += char
        return result
    except Exception:
        raise ValueError("Key Vigenere tidak valid! Pastikan hanya berisi huruf dan tidak kosong.")

# Dekripsi Vigenere Cipher
def vigenere_decrypt(text, key):
    try:
        result = ""
        key = key.lower()
        key_index = 0
        for char in text:
            if char.isalpha():
                shift = ord(key[key_index % len(key)])-97
                base = ord('A') if char.isupper() else ord('a')
                result += chr((ord(char)-base-shift)%26+base)
                key_index += 1
            else:
                result += char
        return result
    except Exception:
        raise ValueError("Key Vigenere tidak valid! Pastikan hanya berisi huruf dan tidak kosong.")

# Generate AES key
def generate_aes_key():
    return Fernet.generate_key().decode()

# Enkripsi AES
def encrypt_aes(msg, key):

    try:
        f = Fernet(key.encode())
        return f.encrypt(msg.encode()).decode()

    except Exception:
        raise ValueError("AES Key tidak valid!")

# Dekripsi AES
def decrypt_aes(cipher, key):

    try:
        f = Fernet(key.encode())
        return f.decrypt(cipher.encode()).decode()

    except Exception:
        raise ValueError("Decrypt AES gagal! Key atau ciphertext salah.")

# Generate RSA key pair
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_key_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()

    public_key_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    return private_key_pem, public_key_pem

# Enkripsi RSA
def encrypt_rsa(message, public_key_pem):

    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode())

        message_bytes = message.encode()

        # Batas payload RSA OAEP SHA-256 untuk key 2048-bit.
        max_length = 190

        if len(message_bytes) > max_length:
            raise ValueError(
                f"Pesan terlalu panjang untuk RSA! Maksimal {max_length} karakter."
            )

        encrypted = public_key.encrypt(
            message_bytes,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return encrypted.hex()

    except Exception as e:
        raise ValueError(f"Encryption failed: {str(e)}")

# Dekripsi RSA
def decrypt_rsa(ciphertext_hex, private_key_pem):
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    return private_key.decrypt(
        bytes.fromhex(ciphertext_hex),
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()

# =========================
# DIGITAL SIGNATURE FUNCTIONS
# =========================
# Membuat digital signature dari pesan menggunakan RSA-PSS + SHA256
def sign_message(message: str, private_key_pem: str) -> str:
    # Muat private key dari string PEM
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None
    )
    # Buat signature menggunakan RSA-PSS dengan hash SHA256
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),   # Mask generation function
            salt_length=padding.PSS.MAX_LENGTH    # Salt length maksimal untuk keamanan optimal
        ),
        hashes.SHA256()   # Algoritma hash pesan
    )
    # Kembalikan signature sebagai hexadecimal agar mudah dibaca & dicopy
    return signature.hex()

# Memverifikasi keaslian digital signature
def verify_signature(message: str, signature_hex: str, public_key_pem: str) -> bool:
    try:
        # Muat public key dari string PEM
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        # Konversi signature dari hex kembali ke bytes
        signature_bytes = bytes.fromhex(signature_hex)
        # Verifikasi signature — akan raise InvalidSignature jika tidak valid
        public_key.verify(
            signature_bytes,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True  # Signature valid
    except Exception:
        return False  # Signature tidak valid / pesan dimodifikasi

# =========================
# UI
# =========================
# Konfigurasi halaman
st.set_page_config(layout="wide")

# Custom CSS untuk Material Design 3 theme seperti tes.html
CSS_FILE = Path(__file__).with_name("style.css")

# Memuat custom CSS
def load_custom_css(css_file=CSS_FILE):
    try:
        css = css_file.read_text(encoding="utf-8")
    except FileNotFoundError:
        st.warning(f"File CSS tidak ditemukan: {css_file.name}")
        return

    st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)


load_custom_css()

# Inisialisasi selected_module di session state
if "selected_module" not in st.session_state:
    st.session_state.selected_module = "embed"

# ========== SIDEBAR ==========
with st.sidebar:
    st.markdown("<div class='sidebar-title' style='font-family: Space Grotesk, sans-serif;'>MODULES</div>", unsafe_allow_html=True)
    
    # Module boxes using columns for better layout
    col1 = st.columns(1)[0]
    
    with col1:
        # Module 01
        if st.button("EMBED", key="btn_embed", use_container_width=True, help="Asset Injection"):
            st.session_state.selected_module = "embed"
        
        # Module 02
        if st.button("EXTRACT", key="btn_extract", use_container_width=True, help="Mission Parameters"):
            st.session_state.selected_module = "extract"
        
        # Module 03
        if st.button("QUALITY", key="btn_quality", use_container_width=True, help="Output Analysis"):
            st.session_state.selected_module = "quality"
        
        # Module 04
        if st.button("CRYPTOGRAPHY", key="btn_crypto", use_container_width=True, help="Cryptography"):
            st.session_state.selected_module = "crypto"

        # Module 05
        if st.button("AUTHENTICATION", key="btn_digsig", use_container_width=True, help="Digital Signature"):
            st.session_state.selected_module = "digsig"
    
    st.markdown("<div style='color:#ff3333; margin-top:30px; font-size:10px; text-align:center; border-top:1px solid #ff3333; padding-top:15px; text-shadow: 0 0 6px rgba(255, 51, 51, 0.4);'>STATUS: ONLINE</div>", unsafe_allow_html=True)

# ========== MAIN CONTENT ==========
st.markdown("""<div class="hud-panel"><h1 style='text-align:center; color:#ff3333; text-shadow: 0 0 20px rgba(255, 51, 51, 0.6); font-family: Space Grotesk, sans-serif;'>IMPOSSIBLE MISSIONS FORCE</h1></div>""", unsafe_allow_html=True)

# ========== MODULE 01: EMBED ==========
if st.session_state.selected_module == "embed":
    st.markdown("<div class='main-header'>MODULE_01: ASSET_INJECTION</div>", unsafe_allow_html=True)
    st.markdown("<div style='color:#ff3333; font-weight:bold; margin-bottom:15px;'>► INITIATE STEGANOGRAPHY EMBEDDING PROTOCOL</div>", unsafe_allow_html=True)
    file=st.file_uploader("Upload Image",type=["png"])
    target=st.text_input("Target")
    location=st.text_input("Location")
    mission=st.text_area("Mission")

    # Pengaturan m-bit
    m_bit=st.selectbox("m-bit",[1,2,3,4])

    # Pengaturan method dan key
    cols=st.columns(2)
    with cols[0]:
        method=st.selectbox("Method",["Random LSB", "Sequential LSB"])
    with cols[1]:
        key=st.text_input("Key",type="password", key="embed_key") if method=="Random LSB" else None

    # Pengaturan self-destruct
    sd = st.checkbox("Self-Destruct")

    # Pengaturan timer jika self-destruct diaktifkan
    timer = st.number_input(
        "Timer (seconds)",
        min_value=1,
        max_value=300,
        value=30,
        step=1
    ) if sd else None

    # Membuat pesan dengan format khusus
    text = format_mission_text(target, location, mission, sd, timer=timer)

    # Validasi upload gambar
    if file:
        file_bytes = file.getvalue()
        try:
            img = load_image(file_bytes)
        except ValueError as exc:
            st.error(str(exc))
            st.stop()
        # Validasi kapasitas pesan
        if len(text) > calculate_message_capacity(img, m_bit):
            st.error(f"Text: {len(text)} / {calculate_message_capacity(img, m_bit)} karakter")
        else:
            st.success(f"Text: {len(text)} / {calculate_message_capacity(img, m_bit)} karakter")

    # Proses embed data
    if st.button("EMBED"):

        # Validasi upload gambar
        if not file:
            st.error("Upload gambar terlebih dahulu sebelum embed!")

        # Validasi key jika menggunakan Random LSB
        elif not is_random_key_valid(method, key):
            st.error("Key wajib diisi untuk Random LSB!")

        else:
            try:
                img = load_image(file.getvalue())
            except ValueError as exc:
                st.error(str(exc))
                st.stop()

            capacity = calculate_message_capacity(img, m_bit)
            msg_len = len(text)

            # Validasi kapasitas pesan
            if msg_len > capacity:
                st.error(f"Pesan terlalu panjang!")
            else:
                # Proses embed data
                stego = embed_message_in_image(img.copy(), text, method, m_bit, key)

                st.image(stego, caption="Stego Image", channels="BGR")

                _, buffer = cv2.imencode(".png", stego)
                st.download_button("Download Stego Image", buffer.tobytes(), "stego-IMF.png", "image/png")

                # Simpan data ke session
                st.session_state.update({
                    "orig": img,
                    "stego": stego
                })

# ========== MODULE 02: EXTRACT ==========
elif st.session_state.selected_module == "extract":
    st.markdown("<div class='main-header'>MODULE_02: MISSION_PARAMETERS</div>", unsafe_allow_html=True)
    st.markdown("<div style='color:#ff3333; font-weight:bold; margin-bottom:15px;'>► EXTRACT CLASSIFIED INTELLIGENCE</div>", unsafe_allow_html=True)
    file = st.file_uploader("Upload Stego Image", type=["png"])

    # Pengaturan m-bit
    m_bit = st.selectbox("m-bit Decode", [1,2,3,4])

    # Pengaturan method dan key
    cols = st.columns(2)
    with cols[0]:
        method = st.selectbox("Method Decode", ["Random LSB", "Sequential LSB"])
    with cols[1]:
        key = None
        if method == "Random LSB":
            key = st.text_input("Key", type="password", key="extract_key")

    # Proses extract data
    if st.button("EXTRACT"):

        # Validasi upload gambar
        if not file:
            st.error("Upload gambar terlebih dahulu sebelum extract!")

        # Validasi key jika menggunakan Random LSB
        elif not is_random_key_valid(method, key):
            st.error("Key wajib diisi untuk Random LSB!")

        # Validasi self-destruct
        else:
            file_bytes = file.getvalue()
            img_hash = calculate_image_hash(file_bytes) # Generate hash dari file yang diupload

            # Inisialisasi consumed_map di session state jika belum ada
            if "consumed_map" not in st.session_state:
                st.session_state["consumed_map"] = {}

            # Cek apakah pesan sudah dihancurkan untuk gambar ini
            if st.session_state["consumed_map"].get(img_hash, False):
                st.error("Pesan sudah dihancurkan untuk gambar ini!")

            else:
                try:
                    img = load_image(file_bytes)
                except ValueError as exc:
                    st.error(str(exc))
                    st.stop()

                msg = extract_message_from_image(img, method, m_bit, key)
                if not msg:
                    st.warning("Tidak ada pesan yang terdeteksi atau format tidak sesuai.")
                else:
                    mission_header = '<div style="padding-bottom:10px;font-family:monospace;color:#ff3333;"><div style="text-align:center;">=== MISSION BRIEF ===</div></div>'
                    header_ph = st.empty()
                    body_ph = st.empty()
                    countdown_ph = st.empty()

                    # Jika pesan memiliki tag [SD:n], tampilkan pesan dan timer, lalu hancurkan pesan setelah timer habis
                    match = re.search(r"\[SD:(\d+)\]", msg)
                    if match:
                        t = int(match.group(1))
                        msg_clean = re.sub(
                            r"\[SD:\d+\]\n?",
                            "",
                            msg
                        )

                        header_ph.markdown(mission_header, unsafe_allow_html=True)
                        body_ph.subheader("SELF-DESTRUCT MESSAGE")
                        body_ph.code(msg_clean, wrap_lines=True)

                        # gunakan timer interaktif agar header/body bisa dihapus setelahnya
                        for remaining in range(t, 0, -1):
                            countdown_ph.warning(f"Pesan akan hilang dalam {remaining} detik...")
                            time.sleep(1)

                        st.session_state["consumed_map"][img_hash] = True


                        # bersihkan placeholder dan tampilkan notifikasi
                        header_ph.empty()
                        body_ph.empty()
                        countdown_ph.empty()
                        st.error("Pesan telah dihancurkan & tidak bisa diakses lagi!")
                    else:
                        header_ph.markdown(mission_header, unsafe_allow_html=True)
                        body_ph.code(msg, wrap_lines=True)

# ========== MODULE 03: QUALITY ==========
elif st.session_state.selected_module == "quality":
    st.markdown("<div class='main-header'>MODULE_03: OUTPUT_ANALYSIS</div>", unsafe_allow_html=True)
    st.markdown("<div style='color:#ff3333; font-weight:bold; margin-bottom:15px;'>► ANALYZE STEGANOGRAPHIC QUALITY METRICS</div>", unsafe_allow_html=True)
    if 'orig' in st.session_state and 'stego' in st.session_state:
        img1 = st.session_state['orig']
        img2 = st.session_state['stego']

        # Hitung metric
        psnr_val = psnr_metric(img1, img2)
        mse_val = mse_metric(img1, img2)
        ssim_val = ssim_metric(img1, img2, channel_axis=2)

        st.markdown("### Quality Metrics", unsafe_allow_html=True)

        c1, c2, c3 = st.columns(3)
        with c1:
            st.metric("PSNR (dB)", f"{psnr_val:.2f}")
            st.markdown(get_psnr_rating_badge(psnr_val), unsafe_allow_html=True)
        with c2:
            st.metric("MSE", f"{mse_val:.4f}")
            st.markdown(get_mse_rating_badge(mse_val), unsafe_allow_html=True)
        with c3:
            st.metric("SSIM", f"{ssim_val:.4f}")
            st.markdown(get_ssim_rating_badge(ssim_val), unsafe_allow_html=True)

        st.subheader("Error Map")
        st.image(create_error_map(img1, img2), clamp=True)

        # Tampil histogram
        st.subheader("Histogram")
        fig, ax = plt.subplots()
        for i in range(3):
            ax.plot(cv2.calcHist([img1],[i],None,[256],[0,256]), linestyle='--')
            ax.plot(cv2.calcHist([img2],[i],None,[256],[0,256]))
        st.pyplot(fig)
        plt.close(fig)

        # Tampil bit-plane
        st.subheader("Bit Plane")
        planes = create_bit_planes(img2)
        cols = st.columns(4)
        for i in range(8):
            cols[i % 4].image(planes[i], caption=f"Bit {i}", clamp=True)
    else:
        st.warning("Silahkan embed terlebih dahulu untuk dianalisis")

# ========== MODULE 04: CRYPTOGRAPHY ==========
elif st.session_state.selected_module == "crypto":
    st.markdown("<div class='main-header'>MODULE_04: CRYPTOGRAPHY_ENGINE</div>", unsafe_allow_html=True)
    st.markdown("<div style='color:#ff3333; font-weight:bold; margin-bottom:15px;'>► MULTI-LAYER ENCRYPTION & DECRYPTION SYSTEM</div>", unsafe_allow_html=True)

    if "layers" not in st.session_state:
        st.session_state.layers=[]
    if "layers_dec" not in st.session_state:
        st.session_state.layers_dec=[]

    # RSA Key Generator
    st.subheader("RSA Key Generator")

    with st.container(horizontal=True) as rsa_cols:
        # Generate RSA key pair dan simpan ke session state
        if st.button("Generate RSA Key"):
            private_key_pem, public_key_pem = generate_rsa_key_pair()
            st.session_state["priv"] = private_key_pem
            st.session_state["pub"] = public_key_pem

        # Hapus RSA key dari session state
        if "priv" in st.session_state and "pub" in st.session_state:
            if st.button("Hapus RSA Key"):
                st.session_state.pop("priv", None)
                st.session_state.pop("pub", None)
                st.rerun()
    
    # Tampilkan RSA key jika ada di session state
    if "pub" in st.session_state and "priv" in st.session_state:
        cols = st.columns(2)
        with cols[0]:
            st.text("Public Key")
            st.code(st.session_state.get("pub",""), height=220)
        with cols[1]:
            st.text("Private Key")
            st.code(st.session_state.get("priv",""), height=220)

    # AES Key Generator
    st.subheader("AES Key Generator")

    with st.container(horizontal=True) as aes_cols:
        # Generate AES key dan simpan ke session state
        if st.button("Generate AES Key"):
            st.session_state["aes_key_global"] = generate_aes_key()

        # Hapus AES key dari session state
        if "aes_key_global" in st.session_state:
            if st.button("Hapus AES Key"):
                st.session_state.pop("aes_key_global", None)
                st.rerun()

    # Tampilkan AES key jika ada di session state
    if "aes_key_global" in st.session_state:
        st.code(st.session_state["aes_key_global"])

    # Tab untuk enkripsi dan dekripsi
    enc_tab, dec_tab = st.tabs(["Encrypt", "Decrypt"])

    # ENCRYPT
    with enc_tab:
        with st.container(horizontal=True) as encryption_action_cols:
            # Tambah layer enkripsi
            if st.button("Add encryption"):
                st.session_state.layers.append({"method": "Vigenere"})

            if st.session_state.layers:
                if st.button("Hapus Layer", key="delete_last_encrypt_layer"):
                    last_idx = len(st.session_state.layers) - 1

                    for key in [
                        f"m{last_idx}",
                        f"s{last_idx}",
                        f"k{last_idx}",
                        f"aes{last_idx}",
                        f"p{last_idx}",
                    ]:
                        st.session_state.pop(key, None)

                    st.session_state.layers.pop()
                    st.rerun()

        # Input pesan
        msg = st.text_area("Message")

        # Pilih metode enkripsi untuk setiap layer
        for i, layer in enumerate(st.session_state.layers):
            st.markdown(f"### Encrypt {i+1}")
            methods = ["Vigenere", "Caesar", "AES", "RSA"]
            layer["method"] = st.selectbox("Method", methods, index=methods.index(layer.get("method", "Vigenere")), key=f"m{i}")

            if layer["method"] == "Caesar":
                layer["shift"] = st.slider("Shift", 1, 25, 3, key=f"s{i}")
            elif layer["method"] == "Vigenere":
                layer["key"] = st.text_input("Key", key=f"k{i}")
            elif layer["method"] == "AES":
                layer["aes_key"] = st.text_input("AES Key", value=st.session_state.get("aes_key_global", ""), key=f"aes{i}")
            else:
                layer["pub"] = st.text_area("Public Key", value=st.session_state.get("pub", ""), key=f"p{i}")

        if st.button("Encrypt"):

            try:
                result = msg

                # Proses enkripsi berlapis
                for layer in st.session_state.layers:

                    if layer["method"] == "Caesar":
                        result = caesar_encrypt(result, layer["shift"])

                    elif layer["method"] == "Vigenere":
                        result = vigenere_encrypt(result, layer["key"])

                    elif layer["method"] == "AES":
                        result = encrypt_aes(result, layer["aes_key"])

                    else:
                        result = encrypt_rsa(result, layer["pub"])

                st.success("Encryption berhasil!")
                st.code(result, wrap_lines=True)

            except Exception as e:
                st.error(str(e))

    # DECRYPT
    with dec_tab:
        with st.container(horizontal=True) as decryption_action_cols:
            # Tambah layer dekripsi
            if st.button("Add decryption"):
                st.session_state.layers_dec.append({"method": "Vigenere"})

            if st.session_state.layers_dec:
                if st.button("Hapus Layer", key="delete_last_decrypt_layer"):
                    last_idx = len(st.session_state.layers_dec) - 1

                    for key in [
                        f"d{last_idx}",
                        f"ds{last_idx}",
                        f"dk{last_idx}",
                        f"daes{last_idx}",
                        f"dp{last_idx}",
                    ]:
                        st.session_state.pop(key, None)

                    st.session_state.layers_dec.pop()
                    st.rerun()

        # Input ciphertext
        cipher = st.text_area("Cipher Message")

        # Pilih metode dekripsi untuk setiap layer
        for i, layer in enumerate(st.session_state.layers_dec):
            st.markdown(f"### Decrypt {i+1}")
            methods = ["Vigenere", "Caesar", "AES", "RSA"]
            layer["method"] = st.selectbox("Method", methods, index=methods.index(layer.get("method", "Vigenere")), key=f"d{i}")

            if layer["method"] == "Caesar":
                layer["shift"] = st.slider("Shift", 1, 25, 3, key=f"ds{i}")
            elif layer["method"] == "Vigenere":
                layer["key"] = st.text_input("Key", key=f"dk{i}")
            elif layer["method"] == "AES":
                layer["aes_key"] = st.text_input("AES Key", value=st.session_state.get("aes_key_global", ""), key=f"daes{i}")
            else:
                layer["priv"] = st.text_area("Private Key", value=st.session_state.get("priv", ""), key=f"dp{i}")

        if st.button("Decrypt"):

            try:
                result = cipher

                # Proses dekripsi berlapis
                for layer in st.session_state.layers_dec:

                    if layer["method"] == "Caesar":
                        result = caesar_decrypt(result, layer["shift"])

                    elif layer["method"] == "Vigenere":
                        result = vigenere_decrypt(result, layer["key"])

                    elif layer["method"] == "AES":
                        result = decrypt_aes(result, layer["aes_key"])

                    else:
                        result = decrypt_rsa(result, layer["priv"])

                st.success("Decrypt berhasil!")
                st.code(result, wrap_lines=True)

            except Exception as e:
                st.error(f"Decrypt gagal! Pastikan urutan layer, key, dan ciphertext sudah benar. ({str(e)})")

# ========== MODULE 05: DIGITAL SIGNATURE ==========
elif st.session_state.selected_module == "digsig":
    st.markdown("<div class='main-header'>MODULE_05: DIGITAL_SIGNATURE</div>", unsafe_allow_html=True)
    st.markdown("<div style='color:#ff3333; font-weight:bold; margin-bottom:15px;'>► RSA-PSS SHA256 — SIGN & VERIFY AUTHENTICITY</div>", unsafe_allow_html=True)

    # ── RSA Key Generator khusus modul ini ───────────────────────────────────
    st.subheader("RSA Key Generator")

    with st.container(horizontal=True) as digsig_cols:
        if st.button("Generate Key Pair", key="digsig_genkey"):
            # Generate pasangan kunci RSA 2048-bit baru dan simpan ke session state
            private_key_pem, public_key_pem = generate_rsa_key_pair()
            st.session_state["ds_priv"] = private_key_pem
            st.session_state["ds_pub"] = public_key_pem

        # Hapus RSA key dari session state
        if "ds_priv" in st.session_state and "ds_pub" in st.session_state:
            if st.button("Hapus RSA Key"):
                st.session_state.pop("ds_priv", None)
                st.session_state.pop("ds_pub", None)
                st.rerun()

    # Tampilkan key pair jika sudah digenerate
    if "ds_priv" in st.session_state and "ds_pub" in st.session_state:
        cols = st.columns(2)
        with cols[0]:
            st.text("Public Key")
            st.code(st.session_state["ds_pub"], height=220)
        with cols[1]:
            st.text("Private Key")
            st.code(st.session_state["ds_priv"], height=220)

        st.markdown("---")

    # ── Tabs Sign & Verify ───────────────────────────────────────────────────
    sign_tab, verify_tab = st.tabs(["Sign", "Verify"])

    # ════════════════════════════════════════════
    # TAB 1 — SIGN MESSAGE
    # ════════════════════════════════════════════
    with sign_tab:
        st.markdown("<div class='panel-header'>► BUAT DIGITAL SIGNATURE</div>", unsafe_allow_html=True)

        # Input pesan yang akan ditandatangani
        sign_message_input = st.text_area(
            "Pesan (Message)",
            placeholder="Masukkan pesan yang ingin ditandatangani...",
            height=120,
            key="ds_msg_sign"
        )

        # Input private key — otomatis terisi jika generate di atas
        sign_private_key = st.text_area("RSA Private Key (PEM)", value=st.session_state.get("ds_priv", ""), height=200, key="ds_privkey_input")

        # Tombol generate signature
        if st.button("🖊 Generate Signature", key="btn_sign", use_container_width=False):
            # Validasi input tidak kosong
            if not sign_message_input.strip():
                st.error("Pesan tidak boleh kosong!")
            elif not sign_private_key.strip():
                st.error("Private key tidak boleh kosong!")
            else:
                try:
                    # Panggil fungsi sign_message untuk membuat signature
                    sig_hex = sign_message(sign_message_input, sign_private_key.strip())
                    # Simpan signature ke session state agar bisa diakses di tab Verify
                    st.session_state["ds_last_sig"] = sig_hex
                    st.session_state["ds_last_msg"] = sign_message_input

                    st.success("Signature berhasil digenerate!")

                    # Tampilkan info metadata signature
                    meta1, meta2, meta3 = st.columns(3)
                    with meta1:
                        st.metric("Algoritma", "RSA-PSS")
                    with meta2:
                        st.metric("Hash", "SHA-256")
                    with meta3:
                        st.metric("Panjang Signature", f"{len(bytes.fromhex(sig_hex)) * 8} bit")

                    # Tampilkan signature hex agar bisa dicopy
                    st.markdown("<span style='color:#ff3333; font-size:12px; font-weight:bold;'>SIGNATURE (Hexadecimal) — Copy untuk Verify:</span>", unsafe_allow_html=True)
                    st.code(sig_hex, language="text")

                    # Visualisasi alur signing
                    st.markdown("""
<div class='hud-panel' style='margin-top:16px;'>
<div class='panel-header'>► ALUR PROSES SIGNING</div>
<span style='color:#ff8888; font-size:12px;'>
① Pesan diubah menjadi hash SHA-256 (256-bit digest)<br>
② Hash dipadding dengan RSA-PSS + random salt untuk keamanan<br>
③ Padded hash dienkripsi dengan Private Key → menghasilkan Signature<br>
④ Signature dikonversi ke Hexadecimal untuk transmisi
</span>
</div>
""", unsafe_allow_html=True)

                except Exception as e:
                    st.error(f"Gagal membuat signature: {str(e)}")

    # ════════════════════════════════════════════
    # TAB 2 — VERIFY SIGNATURE
    # ════════════════════════════════════════════
    with verify_tab:
        st.markdown("<div class='panel-header'>► VERIFIKASI DIGITAL SIGNATURE</div>", unsafe_allow_html=True)

        # Input pesan yang akan diverifikasi
        verify_message_input = st.text_area(
            "Pesan (Message)",
            value=st.session_state.get("ds_last_msg", ""),
            placeholder="Masukkan pesan asli untuk diverifikasi...",
            height=120,
            key="ds_msg_verify"
        )

        # Input signature hex
        verify_sig_input = st.text_area("Signature (Hexadecimal)", value=st.session_state.get("ds_last_sig", ""), height=100, key="ds_sig_input")

        # Input public key
        verify_pubkey_input = st.text_area("RSA Public Key (PEM)", value=st.session_state.get("ds_pub", ""), height=180, key="ds_pubkey_input")

        # Tombol verifikasi signature
        if st.button("Verify Signature", key="btn_verify", use_container_width=False):
            # Validasi semua field terisi
            if not verify_message_input.strip():
                st.error("Pesan tidak boleh kosong!")
            elif not verify_sig_input.strip():
                st.error("Signature tidak boleh kosong!")
            elif not verify_pubkey_input.strip():
                st.error("Public key tidak boleh kosong!")
            else:
                try:
                    # Panggil fungsi verify_signature untuk memvalidasi
                    is_valid = verify_signature(
                        verify_message_input,
                        verify_sig_input.strip(),
                        verify_pubkey_input.strip()
                    )

                    if is_valid:
                        # Signature valid — pesan autentik dan tidak dimodifikasi
                        st.success("Signature VALID — Pesan autentik dan tidak dimodifikasi!")
                        st.markdown("""
<div class='hud-panel' style='border-color: #00ff88; box-shadow: 0 0 12px rgba(0,255,136,0.15);'>
<div class='panel-header' style='color:#00ff88;'>► HASIL VERIFIKASI</div>
<span style='color:#88ffbb; font-size:13px;'>
<b>Integritas terjaga</b> — Pesan tidak berubah sejak ditandatangani<br>
<b>Autentikasi berhasil</b> — Signature dibuat oleh pemilik Private Key yang sesuai<br>
<b>Non-repudiation</b> — Pengirim tidak bisa menyangkal telah menandatangani pesan ini
</span>
</div>
""", unsafe_allow_html=True)
                    else:
                        # Signature tidak valid — pesan telah dimodifikasi atau kunci salah
                        st.error("Pesan sudah dimodifikasi! Signature tidak valid.")
                        st.markdown("""
<div class='hud-panel' style='border-color: #ff3333; box-shadow: 0 0 12px rgba(255,51,51,0.2);'>
<div class='panel-header' style='color:#ff3333;'>► KEMUNGKINAN PENYEBAB KEGAGALAN</div>
<span style='color:#ff8888; font-size:13px;'>
Pesan telah dimodifikasi setelah ditandatangani<br>
Signature tidak sesuai dengan public key yang digunakan<br>
Signature sudah dimanipulasi / corrupt<br>
Public key tidak berpasangan dengan private key yang dipakai untuk sign
</span>
</div>
""", unsafe_allow_html=True)

                except ValueError:
                    st.error("Format signature hex tidak valid! Pastikan signature berupa string hexadecimal.")
                except Exception as e:
                    st.error(f"Verifikasi gagal: {str(e)}")

        # ── Penjelasan alur verify ─────────────────────────────────────────
        st.markdown("""
<div class='hud-panel' style='margin-top:20px;'>
<div class='panel-header'>► CARA KERJA VERIFIKASI</div>
<span style='color:#ff8888; font-size:12px;'>
① Signature (hex) dikonversi kembali ke bytes<br>
② Signature didekripsi menggunakan <b>Public Key</b> → menghasilkan hash asli<br>
③ Pesan yang diinput di-hash ulang dengan SHA-256<br>
④ Kedua hash dibandingkan — jika sama: <b style='color:#00ff88;'>VALID</b>, jika berbeda: <b style='color:#ff3333;'>TIDAK VALID</b>
</span>
</div>
""", unsafe_allow_html=True)

# =========================
# FOOTER
# =========================
st.markdown("<div style='text-align:center; margin-top:80px; color: #ff3333; border-top: 2px solid #ff3333; padding-top: 20px; font-family:monospace; text-shadow: 0 0 8px rgba(255, 51, 51, 0.4);'>\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550<br>Created by <a href='https://www.instagram.com/ibraaidilakbar' target='_blank' style='color: white; text-decoration: none; font-weight: bold;'>Muhammad Ibra Aidil Akbar</a> - 2026<br>\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550</div>", unsafe_allow_html=True)

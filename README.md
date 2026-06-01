# Impossible Missions Force (IMF)

## Deskripsi

Impossible Missions Force (IMF) merupakan aplikasi keamanan informasi berbasis web yang mengintegrasikan teknik Steganografi, Kriptografi, dan Digital Signature untuk menjaga kerahasiaan, integritas, serta keaslian informasi yang dikirimkan melalui media digital.

Aplikasi ini dikembangkan menggunakan Python dan Streamlit dengan konsep pengiriman misi rahasia ala agen intelijen. Pesan dapat disembunyikan ke dalam gambar menggunakan metode Least Significant Bit (LSB), diamankan menggunakan berbagai algoritma kriptografi, serta diverifikasi menggunakan Digital Signature berbasis RSA untuk memastikan bahwa pesan tidak mengalami perubahan selama proses pengiriman.

---

## Fitur Utama

### Steganografi
- Sequential LSB
- Random LSB dengan Key
- Self-Destruct Message
- Pengaturan m-bit (1–4 bit)
- Embed dan Extract Pesan Rahasia

### Analisis Kualitas Citra
- PSNR (Peak Signal-to-Noise Ratio)
- MSE (Mean Squared Error)
- SSIM (Structural Similarity Index)
- Error Map
- Histogram Analysis
- Bit Plane Analysis

### Kriptografi
- Caesar Cipher
- Vigenere Cipher
- AES (Advanced Encryption Standard)
- RSA (Rivest-Shamir-Adleman)
- Multi-Layer Encryption

### Digital Signature
- RSA Digital Signature
- SHA-256 Hashing
- Sign Message
- Verify Signature
- Validasi Integritas Pesan
- Validasi Keaslian Pengirim

---

## Tujuan Pengembangan

Proyek ini dikembangkan untuk:

- Mengimplementasikan teknik Steganografi LSB pada gambar digital.
- Mengimplementasikan algoritma kriptografi klasik dan modern.
- Menggabungkan steganografi dan kriptografi dalam satu sistem keamanan informasi.
- Mengimplementasikan Digital Signature untuk menjamin integritas dan autentikasi pesan.
- Menganalisis kualitas citra setelah proses penyisipan pesan.
- Membangun aplikasi keamanan informasi berbasis web menggunakan Python dan Streamlit.

---

## Teknologi yang Digunakan

### Bahasa Pemrograman
- Python

### Framework
- Streamlit

### Library
- OpenCV
- NumPy
- Matplotlib
- Scikit-Image
- Cryptography
- Hashlib

---

## Instalasi

### Clone Repository

```bash
git clone https://github.com/Ibraaa1311/Project-IMF.git
cd Project-IMF
```

### Install Dependency

```bash
pip install -r requirements.txt
```

### Menjalankan Aplikasi

```bash
streamlit run app.py
```

---

## Struktur Proyek

```text
Project-IMF/
│
├── app.py
├── packages.txt
├── README.md
├── requirements.txt
├── style.css
```

---

## Cara Penggunaan

### 1. Embed Pesan

1. Upload gambar PNG.
2. Isi Target, Location, dan Mission.
3. Pilih metode:
   - Sequential LSB
   - Random LSB
4. Masukkan key jika menggunakan Random LSB.
5. Aktifkan Self-Destruct Message jika diperlukan.
6. Klik tombol **Embed**.
7. Download Stego Image.

---

### 2. Extract Pesan

1. Upload Stego Image.
2. Pilih metode yang sesuai.
3. Masukkan key jika diperlukan.
4. Klik tombol **Extract**.
5. Sistem menampilkan pesan rahasia yang tersimpan.

---

### 3. Analisis Kualitas Gambar

Setelah proses embedding, sistem dapat melakukan analisis:

- PSNR
- MSE
- SSIM
- Error Map
- Histogram Analysis
- Bit Plane Analysis

Analisis ini digunakan untuk mengukur kualitas gambar hasil steganografi dibandingkan dengan gambar asli.

---

### 4. Kriptografi

Sistem menyediakan beberapa algoritma kriptografi:

#### Caesar Cipher
Algoritma klasik berbasis pergeseran karakter.

#### Vigenere Cipher
Algoritma klasik berbasis kunci alfabet.

#### AES
Algoritma kriptografi modern simetris dengan keamanan tinggi.

#### RSA
Algoritma kriptografi modern asimetris menggunakan pasangan Public Key dan Private Key.

#### Multi-Layer Encryption
Pengguna dapat menggabungkan beberapa metode enkripsi secara berlapis untuk meningkatkan keamanan pesan.

---

### 5. Digital Signature

#### Generate Signature

1. Generate RSA Key Pair.
2. Masukkan pesan.
3. Klik tombol **Generate Signature**.
4. Sistem menghasilkan Digital Signature berbentuk hexadecimal.

#### Verify Signature

1. Masukkan pesan.
2. Masukkan Digital Signature.
3. Masukkan Public Key.
4. Klik tombol **Verify Signature**.
5. Sistem akan memverifikasi keaslian dan integritas pesan.

---

## Keamanan Sistem

### Confidentiality (Kerahasiaan)

Dijaga menggunakan:

- AES
- RSA
- Multi-Layer Encryption
- Steganography

### Integrity (Integritas)

Dijaga menggunakan:

- SHA-256
- RSA Digital Signature

### Authentication (Autentikasi)

Dijaga menggunakan:

- RSA Digital Signature
- Public Key Verification

### Concealment (Penyembunyian Informasi)

Dijaga menggunakan:

- Sequential LSB
- Random LSB
- Self-Destruct Message

---

## Hasil Pengujian

Pengujian dilakukan menggunakan beberapa gambar digital dengan ukuran dan kapasitas pesan yang berbeda.

Hasil pengujian menunjukkan bahwa:

- Pesan dapat disisipkan dan diekstrak kembali dengan baik.
- Random LSB memberikan tingkat keamanan yang lebih tinggi dibandingkan Sequential LSB.
- Nilai PSNR tetap tinggi sehingga perubahan visual sulit dibedakan oleh mata manusia.
- Nilai SSIM mendekati 1 yang menunjukkan kualitas gambar tetap terjaga.
- Fitur Self-Destruct Message berhasil menghapus akses terhadap pesan setelah batas waktu tertentu.
- Digital Signature berhasil mendeteksi perubahan isi pesan melalui proses verifikasi.

---

## Repository Source Code

Source code lengkap dapat diakses melalui repository GitHub berikut:

**GitHub Repository:**  
https://github.com/Ibraaa1311/Project-IMF

---

## Pengembang

**Muhammad Ibra Aidil Akbar**  
Program Studi Teknik Informatika  
Konsentrasi Computer Networking

---

## Lisensi

Proyek ini dikembangkan untuk keperluan pembelajaran, penelitian, dan tugas akademik.

Diperbolehkan untuk digunakan sebagai referensi pendidikan dengan tetap mencantumkan sumber pengembang.

import sys
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QLineEdit, QTextEdit, QPushButton, QComboBox, QMessageBox, QFileDialog, QTabWidget, QScrollArea, QStyle)
from PyQt5.QtWinExtras import QtWin
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256, sha1, sha224, sha384, sha512, md5
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import os

class SifrelemeUygulamasi(QMainWindow):
    def __init__(self):
        super().__init__()
        self.arayuz_baslat()

    def arayuz_baslat(self):
        self.setWindowTitle('Şifreleme Programı v1.0.0')
        self.setGeometry(100, 100, 800, 600)
        self.setWindowIcon(QIcon('E:\\VS_CODE\\Python\\cryptography\\secure.ico'))  # Çerçeve ve görev çubuğu ikonu

        app_icon = QIcon('E:\\VS_CODE\\Python\\cryptography\\secure.ico')
        self.setWindowIcon(app_icon)
        QtWin.setCurrentProcessExplicitAppUserModelID('E:\\VS_CODE\\Python\\cryptography\\secure.ico')  # Görev çubuğundaki ikonu değiştirmek için
        app.setWindowIcon(app_icon)

        # Ana widget ve düzen
        self.ana_widget = QWidget()
        self.setCentralWidget(self.ana_widget)
        self.layout = QVBoxLayout(self.ana_widget)

        # Sekme widget'ı
        self.sekmeler = QTabWidget()
        self.layout.addWidget(self.sekmeler)

        # Sekmeler oluşturma
        self.rsa_encrypt_sekmesi_olustur()
        self.rsa_decrypt_sekmesi_olustur()
        self.hash_sekmesi_olustur()
        self.sifreleme_sekmesi_olustur()
        self.bilgi_sekmesi_olustur()

        # Stili ayarlama
        self.setStyleSheet("""
            QWidget {
                background-color: #1e1e1e;
                color: #ffffff;
                font-size: 14px;
            }
            QLineEdit, QTextEdit, QComboBox {
                background-color: #2d2d2d;
                color: #ffffff;
                border: 1px solid #3a3a3a;
            }
            QPushButton {
                background-color: #3a3a3a;
                color: #ffffff;
                border: 1px solid #3a3a3a;
                padding: 5px;
            }
            QPushButton:hover {
                background-color: #4a4a4a;
            }
            QTabWidget::pane {
                border-top: 2px solid #4a4a4a;
                position: absolute;
                top: 0.2em;
                color: #ffffff;
                background: #1e1e1e;
            }
            QTabBar::tab {
                background: #3a3a3a;
                border: 1px solid #3a3a3a;
                padding: 5px;
            }
            QTabBar::tab:selected, QTabBar::tab:hover {
                background: #4a4a4a;
            }
            QMenuBar {
                background-color: #1e1e1e;
                color: #ffffff;
            }
            QMenu {
                background-color: #1e1e1e;
                color: #ffffff;
            }
            QMenu::item:selected {
                background-color: #4a4a4a;
            }
        """)

    def rsa_encrypt_sekmesi_olustur(self):
        self.rsa_encrypt_sekmesi = QWidget()
        self.sekmeler.addTab(self.rsa_encrypt_sekmesi, 'RSA Şifreleme')
        self.rsa_encrypt_dizilimi = QVBoxLayout(self.rsa_encrypt_sekmesi)

        dosya_sec_layout = QHBoxLayout()
        self.dosya_sec_butonu = QPushButton('Şifrelenecek Dosyayı Seç')
        self.dosya_sec_butonu.setIcon(self.style().standardIcon(QStyle.SP_DirOpenIcon))
        self.dosya_sec_butonu.clicked.connect(self.dosya_sec)
        dosya_sec_layout.addWidget(self.dosya_sec_butonu)

        self.secili_dosya_yolu_goster = QLineEdit()
        self.secili_dosya_yolu_goster.setReadOnly(True)
        dosya_sec_layout.addWidget(self.secili_dosya_yolu_goster)

        self.dosya_yolu_sil_butonu = QPushButton('Sil')
        self.dosya_yolu_sil_butonu.setIcon(self.style().standardIcon(QStyle.SP_DialogCancelButton))
        self.dosya_yolu_sil_butonu.clicked.connect(self.dosya_yolu_sil)
        dosya_sec_layout.addWidget(self.dosya_yolu_sil_butonu)

        self.rsa_encrypt_dizilimi.addLayout(dosya_sec_layout)

        self.public_key_etiketi = QLabel('Public Key Girin:')
        self.rsa_encrypt_dizilimi.addWidget(self.public_key_etiketi)
        self.public_key_girdisi = QTextEdit()
        self.rsa_encrypt_dizilimi.addWidget(self.public_key_girdisi)

        self.aes_anahtar_uret_butonu = QPushButton('AES Anahtarı Üret')
        self.aes_anahtar_uret_butonu.setIcon(self.style().standardIcon(QStyle.SP_FileDialogNewFolder))
        self.aes_anahtar_uret_butonu.clicked.connect(self.aes_anahtar_uret)
        self.rsa_encrypt_dizilimi.addWidget(self.aes_anahtar_uret_butonu)

        self.aes_anahtar_metin = QTextEdit()
        self.aes_anahtar_metin.setReadOnly(True)
        self.rsa_encrypt_dizilimi.addWidget(QLabel("AES Anahtar:"))
        self.rsa_encrypt_dizilimi.addWidget(self.aes_anahtar_metin)

        self.dosya_sifrele_butonu = QPushButton('Dosyayı AES ile Şifrele')
        self.dosya_sifrele_butonu.setIcon(self.style().standardIcon(QStyle.SP_FileDialogContentsView))
        self.dosya_sifrele_butonu.clicked.connect(self.dosyayi_aes_ile_sifrele)
        self.rsa_encrypt_dizilimi.addWidget(self.dosya_sifrele_butonu)

        self.sifrelenmis_dosya_yolu_goster = QLineEdit()
        self.sifrelenmis_dosya_yolu_goster.setReadOnly(True)
        self.rsa_encrypt_dizilimi.addWidget(QLabel("Şifrelenmiş Dosya Yolu:"))
        self.rsa_encrypt_dizilimi.addWidget(self.sifrelenmis_dosya_yolu_goster)

        self.aes_anahtar_sifrele_butonu = QPushButton('AES Anahtarını Public Key ile Şifrele')
        self.aes_anahtar_sifrele_butonu.setIcon(self.style().standardIcon(QStyle.SP_FileDialogContentsView))
        self.aes_anahtar_sifrele_butonu.clicked.connect(self.aes_anahtarini_sifrele)
        self.rsa_encrypt_dizilimi.addWidget(self.aes_anahtar_sifrele_butonu)

        self.sifrelenmis_aes_yolu_goster = QLineEdit()
        self.sifrelenmis_aes_yolu_goster.setReadOnly(True)
        self.rsa_encrypt_dizilimi.addWidget(QLabel("Şifrelenmiş AES Anahtarı Yolu:"))
        self.rsa_encrypt_dizilimi.addWidget(self.sifrelenmis_aes_yolu_goster)

        self.eposta_adresi_girdisi = QLineEdit()
        self.rsa_encrypt_dizilimi.addWidget(QLabel("E-posta Adresi:"))
        self.rsa_encrypt_dizilimi.addWidget(self.eposta_adresi_girdisi)

        self.eposta_mesaji_girdisi = QTextEdit()
        self.rsa_encrypt_dizilimi.addWidget(QLabel("E-posta Mesajı:"))
        self.rsa_encrypt_dizilimi.addWidget(self.eposta_mesaji_girdisi)

        self.eposta_gonder_butonu = QPushButton('E-posta Gönder')
        self.eposta_gonder_butonu.setIcon(self.style().standardIcon(QStyle.SP_DialogApplyButton))
        self.eposta_gonder_butonu.clicked.connect(self.eposta_gonder)
        self.rsa_encrypt_dizilimi.addWidget(self.eposta_gonder_butonu)

        self.mail_uyari_etiketi = QLabel("Mesajınız ile birlikte aşağıdaki dosyalar otomatik olarak seçildi ve e-posta ile gönderilecek:\n- Şifrelenmiş Dosya\n- Şifrelenmiş AES Anahtarı")
        self.mail_uyari_etiketi.setStyleSheet("color: red;")
        self.rsa_encrypt_dizilimi.addWidget(self.mail_uyari_etiketi)

    def rsa_decrypt_sekmesi_olustur(self):
        self.rsa_decrypt_sekmesi = QWidget()
        self.sekmeler.addTab(self.rsa_decrypt_sekmesi, 'RSA Çözme')
        self.rsa_decrypt_dizilimi = QVBoxLayout(self.rsa_decrypt_sekmesi)

        self.rsa_anahtar_uret_butonu = QPushButton('RSA Anahtarları Üret')
        self.rsa_anahtar_uret_butonu.setIcon(self.style().standardIcon(QStyle.SP_FileDialogNewFolder))
        self.rsa_anahtar_uret_butonu.clicked.connect(self.rsa_anahtarlar_uret)
        self.rsa_decrypt_dizilimi.addWidget(self.rsa_anahtar_uret_butonu)

        self.acik_anahtar_metin = QTextEdit()
        self.acik_anahtar_metin.setReadOnly(True)
        self.rsa_decrypt_dizilimi.addWidget(QLabel("Açık Anahtar:"))
        self.rsa_decrypt_dizilimi.addWidget(self.acik_anahtar_metin)

        self.ozel_anahtar_metin = QTextEdit()
        self.ozel_anahtar_metin.setReadOnly(True)
        self.rsa_decrypt_dizilimi.addWidget(QLabel("Özel Anahtar:"))
        self.rsa_decrypt_dizilimi.addWidget(self.ozel_anahtar_metin)

        self.sifreli_aes_sec_butonu = QPushButton('Şifreli AES Anahtarını Seç')
        self.sifreli_aes_sec_butonu.setIcon(self.style().standardIcon(QStyle.SP_DirOpenIcon))
        self.sifreli_aes_sec_butonu.clicked.connect(self.sifreli_aes_sec)
        self.rsa_decrypt_dizilimi.addWidget(self.sifreli_aes_sec_butonu)

        self.sifreli_aes_yolu_goster = QLineEdit()
        self.sifreli_aes_yolu_goster.setReadOnly(True)
        self.rsa_decrypt_dizilimi.addWidget(QLabel("Şifreli AES Anahtar Yolu:"))
        self.rsa_decrypt_dizilimi.addWidget(self.sifreli_aes_yolu_goster)

        self.dosya_yolu_sil_butonu_aes = QPushButton('Sil')
        self.dosya_yolu_sil_butonu_aes.setIcon(self.style().standardIcon(QStyle.SP_DialogCancelButton))
        self.dosya_yolu_sil_butonu_aes.clicked.connect(self.dosya_yolu_sil_aes)
        self.rsa_decrypt_dizilimi.addWidget(self.dosya_yolu_sil_butonu_aes)

        self.aes_anahtar_coz_butonu = QPushButton('AES Anahtarını Çöz')
        self.aes_anahtar_coz_butonu.setIcon(self.style().standardIcon(QStyle.SP_FileDialogContentsView))
        self.aes_anahtar_coz_butonu.clicked.connect(self.aes_anahtarini_coz)
        self.rsa_decrypt_dizilimi.addWidget(self.aes_anahtar_coz_butonu)

        self.cozulmus_aes_anahtar_metin = QTextEdit()
        self.cozulmus_aes_anahtar_metin.setReadOnly(True)
        self.rsa_decrypt_dizilimi.addWidget(QLabel("Çözülmüş AES Anahtar:"))
        self.rsa_decrypt_dizilimi.addWidget(self.cozulmus_aes_anahtar_metin)

        self.sifreli_dosya_sec_butonu = QPushButton('Şifreli Dosyayı Seç')
        self.sifreli_dosya_sec_butonu.setIcon(self.style().standardIcon(QStyle.SP_DirOpenIcon))
        self.sifreli_dosya_sec_butonu.clicked.connect(self.sifreli_dosya_sec)
        self.rsa_decrypt_dizilimi.addWidget(self.sifreli_dosya_sec_butonu)

        self.sifreli_dosya_yolu_goster = QLineEdit()
        self.sifreli_dosya_yolu_goster.setReadOnly(True)
        self.rsa_decrypt_dizilimi.addWidget(QLabel("Şifreli Dosya Yolu:"))
        self.rsa_decrypt_dizilimi.addWidget(self.sifreli_dosya_yolu_goster)

        self.dosya_yolu_sil_butonu_dosya = QPushButton('Sil')
        self.dosya_yolu_sil_butonu_dosya.setIcon(self.style().standardIcon(QStyle.SP_DialogCancelButton))
        self.dosya_yolu_sil_butonu_dosya.clicked.connect(self.dosya_yolu_sil_dosya)
        self.rsa_decrypt_dizilimi.addWidget(self.dosya_yolu_sil_butonu_dosya)

        self.dosya_coz_butonu = QPushButton('Dosyayı AES ile Çöz')
        self.dosya_coz_butonu.setIcon(self.style().standardIcon(QStyle.SP_FileDialogContentsView))
        self.dosya_coz_butonu.clicked.connect(self.dosyayi_aes_ile_coz)
        self.rsa_decrypt_dizilimi.addWidget(self.dosya_coz_butonu)

        self.cozulmus_dosya_yolu_goster = QLineEdit()
        self.cozulmus_dosya_yolu_goster.setReadOnly(True)
        self.rsa_decrypt_dizilimi.addWidget(QLabel("Çözülmüş Dosya Yolu:"))
        self.rsa_decrypt_dizilimi.addWidget(self.cozulmus_dosya_yolu_goster)

        self.eposta_adresi_girdisi_decrypt = QLineEdit()
        self.rsa_decrypt_dizilimi.addWidget(QLabel("E-posta Adresi:"))
        self.rsa_decrypt_dizilimi.addWidget(self.eposta_adresi_girdisi_decrypt)

        self.eposta_mesaji_girdisi_decrypt = QTextEdit()
        self.rsa_decrypt_dizilimi.addWidget(QLabel("E-posta Mesajı:"))
        self.rsa_decrypt_dizilimi.addWidget(self.eposta_mesaji_girdisi_decrypt)

        self.eposta_gonder_butonu_decrypt = QPushButton('E-posta Gönder')
        self.eposta_gonder_butonu_decrypt.setIcon(self.style().standardIcon(QStyle.SP_DialogApplyButton))
        self.eposta_gonder_butonu_decrypt.clicked.connect(self.eposta_gonder_decrypt)
        self.rsa_decrypt_dizilimi.addWidget(self.eposta_gonder_butonu_decrypt)

        self.mail_uyari_etiketi_decrypt = QLabel("Mesajınız ile birlikte aşağıdaki dosyalar otomatik olarak seçildi ve e-posta ile gönderilecek:\n- Şifrelenmiş Dosya\n- Şifrelenmiş AES Anahtarı")
        self.mail_uyari_etiketi_decrypt.setStyleSheet("color: red;")
        self.rsa_decrypt_dizilimi.addWidget(self.mail_uyari_etiketi_decrypt)

    def hash_sekmesi_olustur(self):
        self.hash_sekmesi = QWidget()
        self.sekmeler.addTab(self.hash_sekmesi, 'Hash')
        self.hash_dizilimi = QVBoxLayout(self.hash_sekmesi)

        dosya_sec_layout = QHBoxLayout()
        self.dosya_sec_butonu = QPushButton('Dosya Seç')
        self.dosya_sec_butonu.setIcon(self.style().standardIcon(QStyle.SP_DirOpenIcon))
        self.dosya_sec_butonu.clicked.connect(self.dosya_sec_hash)
        dosya_sec_layout.addWidget(self.dosya_sec_butonu)

        self.secili_dosya_yolu_goster_hash = QLineEdit()
        self.secili_dosya_yolu_goster_hash.setReadOnly(True)
        dosya_sec_layout.addWidget(self.secili_dosya_yolu_goster_hash)

        self.dosya_yolu_sil_butonu_hash = QPushButton('Sil')
        self.dosya_yolu_sil_butonu_hash.setIcon(self.style().standardIcon(QStyle.SP_DialogCancelButton))
        self.dosya_yolu_sil_butonu_hash.clicked.connect(self.dosya_yolu_sil_hash)
        dosya_sec_layout.addWidget(self.dosya_yolu_sil_butonu_hash)

        self.hash_dizilimi.addLayout(dosya_sec_layout)

        self.hash_turu_etiketi = QLabel('Hash Türü Seçin:')
        self.hash_turu_combo = QComboBox()
        self.hash_turu_combo.addItems(['MD5', 'SHA-1', 'SHA-224', 'SHA-256', 'SHA-384', 'SHA-512'])
        self.hash_dizilimi.addWidget(self.hash_turu_etiketi)
        self.hash_dizilimi.addWidget(self.hash_turu_combo)

        self.hash_hesapla_butonu = QPushButton('Hash Hesapla')
        self.hash_hesapla_butonu.setIcon(self.style().standardIcon(QStyle.SP_FileDialogContentsView))
        self.hash_hesapla_butonu.clicked.connect(self.hash_hesapla)
        self.hash_dizilimi.addWidget(self.hash_hesapla_butonu)

        self.dosya_hash_etiketi = QLabel('Dosya Hash:')
        self.dosya_hash_metin = QTextEdit()
        self.dosya_hash_metin.setReadOnly(True)
        self.hash_dizilimi.addWidget(self.dosya_hash_etiketi)
        self.hash_dizilimi.addWidget(self.dosya_hash_metin)

        self.girdi_hash_etiketi = QLabel('Girdi Hash:')
        self.girdi_hash_metin = QLineEdit()
        self.hash_dizilimi.addWidget(self.girdi_hash_etiketi)
        self.hash_dizilimi.addWidget(self.girdi_hash_metin)

        self.hash_eslesme_etiketi = QLabel('Hash Eşleşmesi:')
        self.hash_eslesme_metin = QLineEdit()
        self.hash_eslesme_metin.setReadOnly(True)
        self.hash_dizilimi.addWidget(self.hash_eslesme_etiketi)
        self.hash_dizilimi.addWidget(self.hash_eslesme_metin)

    def sifreleme_sekmesi_olustur(self):
        self.sifreleme_sekmesi = QWidget()
        self.sekmeler.addTab(self.sifreleme_sekmesi, 'Şifreleme Yöntemleri')
        self.sifreleme_dizilimi = QVBoxLayout(self.sifreleme_sekmesi)

        self.yontem_etiketi = QLabel('Yöntem Seçin:')
        self.yontem_combo = QComboBox()
        self.yontem_combo.addItems(["Sezar Şifreleme", "Vigenere Şifreleme", "AES", "DES"])
        self.sifreleme_dizilimi.addWidget(self.yontem_etiketi)
        self.sifreleme_dizilimi.addWidget(self.yontem_combo)

        self.girdi_etiketi = QLabel('Girdi Metni:')
        self.girdi_metin = QTextEdit()
        self.sifreleme_dizilimi.addWidget(self.girdi_etiketi)
        self.sifreleme_dizilimi.addWidget(self.girdi_metin)

        self.anahtar_etiketi = QLabel('Anahtar (gerekiyorsa):')
        self.anahtar_girdisi = QLineEdit()
        self.sifreleme_dizilimi.addWidget(self.anahtar_etiketi)
        self.sifreleme_dizilimi.addWidget(self.anahtar_girdisi)

        self.kaydirma_etiketi = QLabel('Kaydırma (Sezar Şifreleme için):')
        self.kaydirma_girdisi = QLineEdit()
        self.sifreleme_dizilimi.addWidget(self.kaydirma_etiketi)
        self.sifreleme_dizilimi.addWidget(self.kaydirma_girdisi)

        self.sifrele_butonu = QPushButton('Şifrele')
        self.sifrele_butonu.setIcon(self.style().standardIcon(QStyle.SP_DialogApplyButton))
        self.sifrele_butonu.clicked.connect(self.sifrele)
        self.sifreleme_dizilimi.addWidget(self.sifrele_butonu)

        self.sifre_coz_butonu = QPushButton('Şifre Çöz')
        self.sifre_coz_butonu.setIcon(self.style().standardIcon(QStyle.SP_DialogApplyButton))
        self.sifre_coz_butonu.clicked.connect(self.sifre_coz)
        self.sifreleme_dizilimi.addWidget(self.sifre_coz_butonu)

        self.cikti_etiketi = QLabel('Çıktı Metni:')
        self.cikti_metin = QTextEdit()
        self.sifreleme_dizilimi.addWidget(self.cikti_etiketi)
        self.sifreleme_dizilimi.addWidget(self.cikti_metin)

    def bilgi_sekmesi_olustur(self):
        self.bilgi_sekmesi = QWidget()
        self.sekmeler.addTab(self.bilgi_sekmesi, 'Bilgi')
        bilgi_dizilimi = QVBoxLayout(self.bilgi_sekmesi)

        bilgi_metin = QTextEdit()
        bilgi_metin.setReadOnly(True)
        bilgi_metin.setPlainText(
        """"Bu program, staj yaptığım firmada IT Departman Mühendisi Melih Bey tarafından benden istendi. 
        **Programın taşınabilir aygıtların veri güvenliğini sağlamak, veri çalınmasını önlemek ve veri kaybını önlemek açısından gerekli olduğu** belirtildi. 
        Programın kısa dönem staj süresince tamamen bitirilemeyeceğini göz önünde bulundurarak, uygulamalara entegre olma ve diğer durumlardan bahsederek, programın başından sonuna kadar detaylı bir bilgi vereceğim.

        Program Özellikleri:

        - **RSA Şifreleme ve Çözme:** RSA algoritması kullanarak metin ve dosya şifreleme ve çözme işlemleri gerçekleştirilir. 
        RSA, asimetrik bir şifreleme algoritmasıdır ve güvenli anahtar değişimi için yaygın olarak kullanılır. 
        Asimetrik şifrelemede iki anahtar kullanılır: birisi açık anahtar (public key), diğeri ise özel anahtar (private key). 
        Açık anahtar ile şifrelenen veri, yalnızca özel anahtar ile çözülebilir, bu da RSA algoritmasını güvenli anahtar değişimi için ideal kılar. 
        RSA şifrelemesi, özellikle hassas verilerin güvenli bir şekilde iletilmesi gereken durumlarda etkilidir. 
        Örneğin, bir kişi başka bir kişiye güvenli bir mesaj göndermek istediğinde, alıcının açık anahtarı ile mesajı şifreleyebilir ve alıcı, kendi özel anahtarını kullanarak mesajı çözebilir.

        - **AES ile Dosya Şifreleme ve Çözme:** Advanced Encryption Standard (AES) kullanarak dosyaların şifrelenmesi ve çözülmesi sağlanır. 
        AES, simetrik bir şifreleme algoritması olup, veri güvenliği açısından yüksek bir koruma sağlar. 
        AES, blok şifreleme yöntemi kullanır ve 128, 192 veya 256 bit anahtar uzunluklarına sahip olabilir. 
        Simetrik şifrelemede aynı anahtar hem şifreleme hem de şifre çözme işlemleri için kullanılır, bu nedenle anahtarın güvenli bir şekilde paylaşılması gereklidir. 
        AES şifrelemesi, verilerin güvenli bir şekilde saklanması ve iletilmesi için kullanılır. 
        Özellikle büyük dosyaların şifrelenmesi ve çözümlenmesi için etkili bir yöntemdir.

        - **Hash Hesaplama ve Karşılaştırma:** MD5, SHA-1, SHA-224, SHA-256, SHA-384 ve SHA-512 gibi çeşitli hash algoritmaları kullanılarak dosya ve metinlerin hash değerleri hesaplanabilir ve bu değerler karşılaştırılabilir. 
        Bu özellik, veri bütünlüğünün sağlanmasında önemli bir rol oynar. 
        Hash fonksiyonları, bir girdiden sabit uzunlukta bir çıktı üretir ve bu çıktı, girdinin dijital parmak izi olarak kullanılır. 
        Veri aktarımı veya depolama sırasında veri bütünlüğünün korunup korunmadığını kontrol etmek için hash değerleri karşılaştırılabilir. 
        Hash hesaplama, veri değişikliklerini tespit etmek ve veri bütünlüğünü sağlamak için kullanılır. 
        Örneğin, bir dosyanın orijinalliğini doğrulamak için dosyanın hash değeri hesaplanabilir ve bilinen hash değeri ile karşılaştırılabilir.

        - **Sezar ve Vigenere Şifreleme ve Çözme:** Sezar ve Vigenere algoritmaları kullanılarak metin şifreleme ve çözme işlemleri yapılabilir. 
        Sezar şifrelemesi, her harfi belirli bir sayıda kaydırarak şifreler. 
        Vigenere şifrelemesi ise bir anahtar kelime kullanarak şifreleme işlemi yapar. 
        Bu algoritmalar, tarihsel olarak önemli olsalar da günümüzde basitlikleri nedeniyle eğitim ve temel şifreleme uygulamaları için kullanılmaktadır. 
        Sezar ve Vigenere şifrelemesi, temel kriptografi eğitimi ve kişisel veri güvenliği için uygundur. 
        Örneğin, bir kişi basit bir mesajı şifrelemek istediğinde bu algoritmaları kullanabilir.

        - **Şifrelenmiş Dosya ve Anahtarın E-posta ile Gönderimi:** Şifrelenmiş dosyalar ve anahtarlar, kullanıcı tarafından belirtilen e-posta adresine güvenli bir şekilde gönderilebilir. 
        Bu özellik, özellikle hassas verilerin güvenli bir şekilde paylaşılmasında kullanışlıdır. 
        E-posta ile gönderim sırasında dosyaların ve anahtarların güvenliğini sağlamak için ek önlemler alınabilir. 
        Bu özellik, kullanıcıların şifrelenmiş verileri güvenli bir şekilde paylaşmasına olanak tanır. 
        Örneğin, bir kullanıcı önemli bir dosyayı şifreleyip, şifrelenmiş dosya ve anahtarı alıcıya güvenli bir şekilde gönderebilir.

        **Programın Çalışma Prensibi:**

        - **RSA Şifreleme:** Kullanıcı, şifrelenecek dosyayı ve alıcının public key'ini seçer. 
        AES anahtarı oluşturulur ve dosya AES ile şifrelenir. 
        AES anahtarı, alıcının public key'i ile şifrelenir ve hem şifrelenmiş dosya hem de şifrelenmiş AES anahtarı alıcıya gönderilir.

        - **RSA Şifre Çözme:** Kullanıcı, şifrelenmiş AES anahtarını ve şifrelenmiş dosyayı seçer. 
        Kendi private key'ini kullanarak AES anahtarını çözer ve bu anahtarla dosyayı deşifre eder.

        - **AES Şifreleme:** Kullanıcı, şifrelenecek dosyayı ve AES anahtarını girer. 
        Dosya, AES algoritması kullanılarak şifrelenir ve şifrelenmiş dosya kaydedilir.

        - **AES Şifre Çözme:** Kullanıcı, şifrelenmiş dosyayı ve AES anahtarını girer. 
        Dosya, AES algoritması kullanılarak deşifre edilir ve orijinal dosya kaydedilir.

        - **Hash Hesaplama:** Kullanıcı, hash türünü ve dosyayı seçer. 
        Dosyanın hash değeri hesaplanır ve kullanıcıya gösterilir.

        - **Hash Karşılaştırma:** Kullanıcı, hash türünü ve dosyayı seçer. 
        Dosyanın hash değeri, kullanıcının girdiği hash değeriyle karşılaştırılır ve sonuç gösterilir.

        - **Sezar ve Vigenere Şifreleme:** Kullanıcı, şifrelenecek metni ve anahtarı girer. 
        Sezar veya Vigenere algoritması kullanılarak metin şifrelenir ve kullanıcıya gösterilir.

        - **Sezar ve Vigenere Şifre Çözme:** Kullanıcı, şifrelenmiş metni ve anahtarı girer. 
        Sezar veya Vigenere algoritması kullanılarak metin deşifre edilir ve kullanıcıya gösterilir.

        **Bu program, veri güvenliğinin kritik öneme sahip olduğu günümüzde, kullanıcıların verilerini güvenli bir şekilde şifreleyip çözmelerine ve güvenli bir şekilde paylaşmalarına olanak tanımaktadır.** 
        Programın geliştirilme süreci boyunca, kullanıcı geri bildirimleri ve sürekli iyileştirmeler ile programın güvenliği ve işlevselliği artırılacaktır. 
        Kullanıcı dostu ve modern arayüzü ile program, veri güvenliği ihtiyaçlarını etkili bir şekilde karşılayacaktır.

        Staj süresince programın tam anlamıyla bitirilemeyeceği göz önüne alınarak, şu anki sürümde temel işlevsellikler sağlanmış ve gelecek geliştirmelere açık bir yapı bırakılmıştır. 
        Bu süreçte programın farklı uygulamalarla entegre edilmesi, kullanıcı geri bildirimleriyle geliştirilmesi ve ek özelliklerin eklenmesi planlanmaktadır. 
        Örneğin, daha gelişmiş şifreleme algoritmaları, bulut depolama entegrasyonu ve gelişmiş kullanıcı arayüzü gibi eklemeler düşünülebilir. 
        İleride program geliştikçe, çeşitli uygulamalara ve işletmelere entegre edilerek daha geniş bir kullanım alanına sahip olması hedeflenmektedir.

        Programın geliştirilme süreci boyunca, kullanıcı geri bildirimleri dikkate alınarak sürekli iyileştirmeler yapılacaktır. 
        Kullanıcıların ihtiyaçlarına yanıt verebilmek için programın işlevselliği ve güvenliği sürekli olarak gözden geçirilecek ve güncellenecektir. 
        Gelecek planlar arasında, daha gelişmiş şifreleme algoritmalarının eklenmesi, kullanıcının şifreleme ve şifre çözme işlemlerini daha kolay ve hızlı bir şekilde gerçekleştirmesini sağlayacak otomasyonların geliştirilmesi yer almaktadır. 
        Ayrıca, programın farklı dillerde desteklenmesi ve uluslararası kullanıcıların da programı kullanabilmesi hedeflenmektedir.

        Programın etkili bir şekilde kullanılabilmesi için, kullanıcı eğitimi ve destek hizmetleri sunulacaktır. 
        Kullanıcıların programı nasıl kullanacaklarına dair ayrıntılı dökümantasyonlar ve video eğitimleri hazırlanacaktır. 
        Ayrıca, kullanıcıların karşılaştıkları sorunları hızlı bir şekilde çözebilmeleri için bir destek ekibi oluşturulacaktır. 
        Bu destek ekibi, kullanıcıların teknik sorunlarını çözmelerine yardımcı olacak ve programın etkin bir şekilde kullanılmasını sağlayacaktır.

        Gmail: rasitbilgili43@gmail.com"""""
        )
        bilgi_dizilimi.addWidget(bilgi_metin)

    def dosya_sec(self):
        dosya_yolu, _ = QFileDialog.getOpenFileName(self, "Dosya Seç", "", "Tüm Dosyalar (*)")
        if dosya_yolu:
            self.secili_dosya_yolu = dosya_yolu
            self.secili_dosya_yolu_goster.setText(dosya_yolu)

    def dosya_sec_hash(self):
        dosya_yolu, _ = QFileDialog.getOpenFileName(self, "Dosya Seç", "", "Tüm Dosyalar (*)")
        if dosya_yolu:
            self.secili_dosya_yolu_hash = dosya_yolu
            self.secili_dosya_yolu_goster_hash.setText(dosya_yolu)

    def hash_hesapla(self):
        if not hasattr(self, 'secili_dosya_yolu_hash') or not self.secili_dosya_yolu_hash:
            QMessageBox.critical(self, "Hata", "Dosya seçilmedi")
            return

        hash_turu = self.hash_turu_combo.currentText()
        dosya_hash = dosya_hash_hesapla(self.secili_dosya_yolu_hash, hash_turu)
        self.dosya_hash_metin.setPlainText(dosya_hash)

        girdi_hash = self.girdi_hash_metin.text().strip()
        if girdi_hash:
            hashler_eslesiyor = (dosya_hash == girdi_hash)
            self.hash_eslesme_metin.setText("Evet" if hashler_eslesiyor else "Hayır")
        else:
            self.hash_eslesme_metin.setText("")

    def rsa_anahtarlar_uret(self):
        ozel_anahtar, acik_anahtar = rsa_anahtarlar_uret()
        self.ozel_anahtar_metin.setPlainText(ozel_anahtar.decode())
        self.acik_anahtar_metin.setPlainText(acik_anahtar.decode())

    def aes_anahtar_uret(self):
        aes_anahtar = os.urandom(32)
        self.aes_anahtar = aes_anahtar
        self.aes_anahtar_metin.setPlainText(aes_anahtar.hex())

    def dosyayi_aes_ile_sifrele(self):
        if not hasattr(self, 'secili_dosya_yolu') or not self.secili_dosya_yolu:
            QMessageBox.critical(self, "Hata", "Dosya seçilmedi")
            return

        if not hasattr(self, 'aes_anahtar'):
            QMessageBox.critical(self, "Hata", "AES anahtarı üretilmedi")
            return

        try:
            with open(self.secili_dosya_yolu, 'rb') as dosya:
                veri = dosya.read()
                aes_sifreleyici = AES.new(self.aes_anahtar, AES.MODE_EAX)
                sifreli_veri, etiket = aes_sifreleyici.encrypt_and_digest(pad(veri, AES.block_size))
                self.sifrelenmis_dosya_yolu = self.secili_dosya_yolu + '.enc'
                with open(self.sifrelenmis_dosya_yolu, 'wb') as sifreli_dosya:
                    for x in (aes_sifreleyici.nonce, etiket, sifreli_veri):
                        sifreli_dosya.write(x)
                self.sifrelenmis_dosya_yolu_goster.setText(self.sifrelenmis_dosya_yolu)
                QMessageBox.information(self, "Dosya Şifrelendi", f"Şifrelenmiş dosya {self.sifrelenmis_dosya_yolu} olarak kaydedildi")
        except Exception as e:
            QMessageBox.critical(self, "Hata", str(e))

    def aes_anahtarini_sifrele(self):
        if not hasattr(self, 'aes_anahtar'):
            QMessageBox.critical(self, "Hata", "AES anahtarı üretilmedi")
            return

        acik_anahtar_pem = self.public_key_girdisi.toPlainText().encode()
        try:
            acik_anahtar = serialization.load_pem_public_key(acik_anahtar_pem)
            sifrelenmis_aes_anahtari = acik_anahtar.encrypt(
                self.aes_anahtar,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            self.sifrelenmis_aes_yolu = self.secili_dosya_yolu + '_aes.enc'
            with open(self.sifrelenmis_aes_yolu, 'wb') as aes_dosya:
                aes_dosya.write(sifrelenmis_aes_anahtari)
            self.sifrelenmis_aes_yolu_goster.setText(self.sifrelenmis_aes_yolu)
            QMessageBox.information(self, "AES Anahtarı Şifrelendi", f"Şifrelenmiş AES anahtarı {self.sifrelenmis_aes_yolu} olarak kaydedildi")
        except Exception as e:
            QMessageBox.critical(self, "Hata", str(e))

    def sifreli_aes_sec(self):
        dosya_yolu, _ = QFileDialog.getOpenFileName(self, "Şifreli AES Anahtarını Seç", "", "Şifrelenmiş Dosyalar (*.enc);;Tüm Dosyalar (*)")
        if dosya_yolu:
            self.sifreli_aes_yolu = dosya_yolu
            self.sifreli_aes_yolu_goster.setText(dosya_yolu)

    def sifreli_dosya_sec(self):
        dosya_yolu, _ = QFileDialog.getOpenFileName(self, "Şifreli Dosyayı Seç", "", "Şifrelenmiş Dosyalar (*.enc);;Tüm Dosyalar (*)")
        if dosya_yolu:
            self.sifrelenmis_dosya_yolu = dosya_yolu
            self.sifreli_dosya_yolu_goster.setText(dosya_yolu)

    def aes_anahtarini_coz(self):
        if not hasattr(self, 'sifreli_aes_yolu') or not self.sifreli_aes_yolu:
            QMessageBox.critical(self, "Hata", "Şifreli AES anahtarı seçilmedi")
            return

        ozel_anahtar_pem = self.ozel_anahtar_metin.toPlainText().encode()
        try:
            ozel_anahtar = serialization.load_pem_private_key(ozel_anahtar_pem, password=None)
            with open(self.sifreli_aes_yolu, 'rb') as aes_dosya:
                sifrelenmis_aes_anahtari = aes_dosya.read()
                aes_anahtar = ozel_anahtar.decrypt(
                    sifrelenmis_aes_anahtari,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                self.aes_anahtar = aes_anahtar
                self.cozulmus_aes_anahtar_metin.setPlainText(aes_anahtar.hex())
                QMessageBox.information(self, "AES Anahtarı Çözüldü", "AES anahtarı başarıyla çözüldü")
        except Exception as e:
            QMessageBox.critical(self, "Hata", str(e))

    def dosyayi_aes_ile_coz(self):
        if not hasattr(self, 'sifrelenmis_dosya_yolu') or not self.sifrelenmis_dosya_yolu:
            QMessageBox.critical(self, "Hata", "Şifrelenmiş dosya seçilmedi")
            return

        if not hasattr(self, 'aes_anahtar'):
            QMessageBox.critical(self, "Hata", "AES anahtarı çözülmedi")
            return

        try:
            with open(self.sifrelenmis_dosya_yolu, 'rb') as sifreli_dosya:
                nonce, etiket, sifreli_veri = [sifreli_dosya.read(x) for x in (16, 16, -1)]
                aes_sifreleyici = AES.new(self.aes_anahtar, AES.MODE_EAX, nonce=nonce)
                cozulmus_veri = unpad(aes_sifreleyici.decrypt_and_verify(sifreli_veri, etiket), AES.block_size)
                self.cozulmus_dosya_yolu = self.sifrelenmis_dosya_yolu + '.dec'
                with open(self.cozulmus_dosya_yolu, 'wb') as dosya:
                    dosya.write(cozulmus_veri)
                self.cozulmus_dosya_yolu_goster.setText(self.cozulmus_dosya_yolu)
                QMessageBox.information(self, "Dosya Çözüldü", f"Çözülmüş dosya {self.cozulmus_dosya_yolu} olarak kaydedildi")
        except Exception as e:
            QMessageBox.critical(self, "Hata", str(e))

    def eposta_gonder(self):
        if not hasattr(self, 'sifrelenmis_aes_yolu') or not self.sifrelenmis_aes_yolu:
            QMessageBox.critical(self, "Hata", "Şifrelenmiş AES anahtarı mevcut değil")
            return

        if not hasattr(self, 'sifrelenmis_dosya_yolu') or not self.sifrelenmis_dosya_yolu:
            QMessageBox.critical(self, "Hata", "Şifrelenmiş dosya mevcut değil")
            return

        eposta_adresi = self.eposta_adresi_girdisi.text()
        eposta_mesaji = self.eposta_mesaji_girdisi.toPlainText()

        if not eposta_adresi:
            QMessageBox.critical(self, "Hata", "E-posta adresi girilmedi")
            return

        if not eposta_mesaji.strip():
            QMessageBox.critical(self, "Hata", "E-posta mesajı boş olamaz")
            return

        try:
            msg = MIMEMultipart()
            msg['From'] = 'MS_MbustC@trial-vywj2lpyoxkl7oqz.mlsender.net'
            msg['To'] = eposta_adresi
            msg['Subject'] = 'Şifrelenmiş Dosya ve AES Anahtarı'

            body = eposta_mesaji
            msg.attach(MIMEText(body, 'plain'))

            with open(self.sifrelenmis_dosya_yolu, 'rb') as dosya:
                attachment = MIMEBase('application', 'octet-stream')
                attachment.set_payload(dosya.read())
                encoders.encode_base64(attachment)
                attachment.add_header('Content-Disposition', f'attachment; filename={os.path.basename(self.sifrelenmis_dosya_yolu)}')
                msg.attach(attachment)

            with open(self.sifrelenmis_aes_yolu, 'rb') as aes_dosya:
                aes_attachment = MIMEBase('application', 'octet-stream')
                aes_attachment.set_payload(aes_dosya.read())
                encoders.encode_base64(aes_attachment)
                aes_attachment.add_header('Content-Disposition', 'attachment; filename=aes_key.enc')
                msg.attach(aes_attachment)

            server = smtplib.SMTP('smtp.mailersend.net', 587)
            server.starttls()
            server.login('MS_MbustC@trial-vywj2lpyoxkl7oqz.mlsender.net', '2dJh2y9mMbni61NT')
            text = msg.as_string()
            server.sendmail('MS_MbustC@trial-vywj2lpyoxkl7oqz.mlsender.net', eposta_adresi, text)
            server.quit()

            QMessageBox.information(self, "E-posta Gönderildi", "E-posta belirtilen adrese gönderildi")
        except Exception as e:
            QMessageBox.critical(self, "Hata", str(e))

    def eposta_gonder_decrypt(self):
        eposta_adresi = self.eposta_adresi_girdisi_decrypt.text()
        eposta_mesaji = self.eposta_mesaji_girdisi_decrypt.toPlainText()

        if not eposta_adresi:
            QMessageBox.critical(self, "Hata", "E-posta adresi girilmedi")
            return

        if not eposta_mesaji.strip():
            QMessageBox.critical(self, "Hata", "E-posta mesajı boş olamaz")
            return

        try:
            msg = MIMEMultipart()
            msg['From'] = 'MS_MbustC@trial-vywj2lpyoxkl7oqz.mlsender.net'
            msg['To'] = eposta_adresi
            msg['Subject'] = 'Public Key ve Mesaj'

            body = eposta_mesaji
            msg.attach(MIMEText(body, 'plain'))

            public_key = self.acik_anahtar_metin.toPlainText()
            public_key_attachment = MIMEText(public_key, 'plain')
            public_key_attachment.add_header('Content-Disposition', 'attachment; filename=public_key.pem')
            msg.attach(public_key_attachment)

            server = smtplib.SMTP('smtp.mailersend.net', 587)
            server.starttls()
            server.login('MS_MbustC@trial-vywj2lpyoxkl7oqz.mlsender.net', '2dJh2y9mMbni61NT')
            text = msg.as_string()
            server.sendmail('MS_MbustC@trial-vywj2lpyoxkl7oqz.mlsender.net', eposta_adresi, text)
            server.quit()

            QMessageBox.information(self, "E-posta Gönderildi", "E-posta belirtilen adrese gönderildi")
        except Exception as e:
            QMessageBox.critical(self, "Hata", str(e))

    def sifrele(self):
        yontem = self.yontem_combo.currentText()
        metin = self.girdi_metin.toPlainText()
        anahtar = self.anahtar_girdisi.text()
        kaydirma = int(self.kaydirma_girdisi.text()) if self.kaydirma_girdisi.text().isdigit() else 0
        sonuc = ""

        if yontem == "Sezar Şifreleme":
            sonuc = sezar_sifrele(metin, kaydirma)
        elif yontem == "Vigenere Şifreleme":
            sonuc = vigenere_sifrele(metin, anahtar)
        elif yontem == "AES":
            sonuc = aes_sifrele(metin, anahtar)
        elif yontem == "DES":
            sonuc = des_sifrele(metin, anahtar)

        self.cikti_metin.setPlainText(sonuc)

    def sifre_coz(self):
        yontem = self.yontem_combo.currentText()
        metin = self.girdi_metin.toPlainText()
        anahtar = self.anahtar_girdisi.text()
        kaydirma = int(self.kaydirma_girdisi.text()) if self.kaydirma_girdisi.text().isdigit() else 0
        sonuc = ""

        if yontem == "Sezar Şifreleme":
            sonuc = sezar_sifre_coz(metin, kaydirma)
        elif yontem == "Vigenere Şifreleme":
            sonuc = vigenere_sifre_coz(metin, anahtar)
        elif yontem == "AES":
            sonuc = aes_sifre_coz(metin, anahtar)
        elif yontem == "DES":
            sonuc = des_sifre_coz(metin, anahtar)
        else:
            QMessageBox.critical(self, "Hata", "Bu yöntemle şifre çözme yapılamaz")

        self.cikti_metin.setPlainText(sonuc)

    def dosya_yolu_sil(self):
        self.secili_dosya_yolu = ""
        self.secili_dosya_yolu_goster.clear()

    def dosya_yolu_sil_hash(self):
        self.secili_dosya_yolu_hash = ""
        self.secili_dosya_yolu_goster_hash.clear()

    def dosya_yolu_sil_aes(self):
        self.sifreli_aes_yolu = ""
        self.sifreli_aes_yolu_goster.clear()

    def dosya_yolu_sil_dosya(self):
        self.sifrelenmis_dosya_yolu = ""
        self.sifreli_dosya_yolu_goster.clear()

def sezar_sifrele(duz_metin, kaydirma):
    sifreli_metin = ""
    for char in duz_metin:
        if char.isalpha():
            kaydirma_baz = 65 if char.isupper() else 97
            sifreli_metin += chr((ord(char) - kaydirma_baz + kaydirma) % 26 + kaydirma_baz)
        else:
            sifreli_metin += char
    return sifreli_metin

def sezar_sifre_coz(sifreli_metin, kaydirma):
    return sezar_sifrele(sifreli_metin, -kaydirma)

def vigenere_sifrele(duz_metin, anahtar):
    sifreli_metin = ""
    anahtar_indeks = 0
    for char in duz_metin:
        if char.isalpha():
            kaydirma_baz = 65 if char.isupper() else 97
            anahtar_kaydirma = ord(anahtar[anahtar_indeks % len(anahtar)].lower()) - 97
            sifreli_metin += chr((ord(char) - kaydirma_baz + anahtar_kaydirma) % 26 + kaydirma_baz)
            anahtar_indeks += 1
        else:
            sifreli_metin += char
    return sifreli_metin

def vigenere_sifre_coz(sifreli_metin, anahtar):
    cozulmus_metin = ""
    anahtar_indeks = 0
    for char in sifreli_metin:
        if char.isalpha():
            kaydirma_baz = 65 if char.isupper() else 97
            anahtar_kaydirma = ord(anahtar[anahtar_indeks % len(anahtar)].lower()) - 97
            cozulmus_metin += chr((ord(char) - kaydirma_baz - anahtar_kaydirma + 26) % 26 + kaydirma_baz)
            anahtar_indeks += 1
        else:
            cozulmus_metin += char
    return cozulmus_metin

def aes_sifrele(duz_metin, anahtar):
    sifreleyici = AES.new(pad(anahtar.encode(), 16), AES.MODE_ECB)
    sifreli_metin = sifreleyici.encrypt(pad(duz_metin.encode(), 16))
    return sifreli_metin.hex()

def aes_sifre_coz(sifreli_metin, anahtar):
    sifreleyici = AES.new(pad(anahtar.encode(), 16), AES.MODE_ECB)
    cozulmus_metin = unpad(sifreleyici.decrypt(bytes.fromhex(sifreli_metin)), 16)
    return cozulmus_metin.decode()

def des_sifrele(duz_metin, anahtar):
    sifreleyici = DES.new(pad(anahtar.encode(), 8), DES.MODE_ECB)
    sifreli_metin = sifreleyici.encrypt(pad(duz_metin.encode(), 8))
    return sifreli_metin.hex()

def des_sifre_coz(sifreli_metin, anahtar):
    sifreleyici = DES.new(pad(anahtar.encode(), 8), DES.MODE_ECB)
    cozulmus_metin = unpad(sifreleyici.decrypt(bytes.fromhex(sifreli_metin)), 8)
    return cozulmus_metin.decode()

def dosya_hash_hesapla(dosya_yolu, hash_turu):
    hash_fonksiyonu = {
        'MD5': md5,
        'SHA-1': sha1,
        'SHA-224': sha224,
        'SHA-256': sha256,
        'SHA-384': sha384,
        'SHA-512': sha512
    }[hash_turu]
    with open(dosya_yolu, 'rb') as dosya:
        dosya_hash = hash_fonksiyonu()
        while chunk := dosya.read(8192):
            dosya_hash.update(chunk)
    return dosya_hash.hexdigest()

def rsa_anahtarlar_uret():
    ozel_anahtar = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    acik_anahtar = ozel_anahtar.public_key()

    pem_ozel = ozel_anahtar.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    pem_acik = acik_anahtar.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return pem_ozel, pem_acik

if __name__ == '__main__':
    app = QApplication(sys.argv)
    pencere = SifrelemeUygulamasi()
    pencere.show()
    sys.exit(app.exec_())

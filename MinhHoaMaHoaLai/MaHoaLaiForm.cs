using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace MinhHoaMaHoaLai
{
    public partial class MaHoaLaiForm : Form
    {
        public MaHoaLaiForm()
        {
            InitializeComponent();

            // Thêm sự kiện điền giá trị cho txtP và txtQ sau khi nhập p , q
            txtP.TextChanged += new EventHandler(txtP_or_txtQ_TextChanged);
            txtQ.TextChanged += new EventHandler(txtP_or_txtQ_TextChanged);

        }
        private void txtP_or_txtQ_TextChanged(object sender, EventArgs e)
        {
            // Kiểm tra  p , q và tính n , z 
            if (int.TryParse(txtP.Text, out int p) && int.TryParse(txtQ.Text, out int q))
            {
                if (p > 1 && q > 1) 
                {
                    // Tính n và z
                    int n = p * q;
                    int z = (p - 1) * (q - 1);

                    // Hiển thị n và z
                    txtN.Text = n.ToString();
                    txtZ.Text = z.ToString();
                }
            }
        }
       
        // Mã hóa bất đối xứng RSA
        public class RSA
        {
            public int p { get; set; }
            public int q { get; set; }
            public int n { get; private set; }
            public int z { get; private set; }
            public int e { get; set; }
            public int d { get; private set; }

            public RSA(int p, int q, int e, int d)
            {
                this.p = p;
                this.q = q;
                this.n = p * q;
                this.z = (p - 1) * (q - 1);
                this.e = e;
                this.d = d;

                if (!IsValidE(e, z))
                {
                    MessageBox.Show("Giá trị E không hợp lệ .", "Thông báo lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }

                if (!IsValidD(e, d, z))
                {
                    MessageBox.Show("Giá trị D không hợp lệ .", "Thông báo lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }

            // Kiểm tra tính hợp lệ của e
            private bool IsValidE(int e, int z)
            {
                return e > 1 && e < z && GCD(e, z) == 1;
            }

            // Kiểm tra tính hợp lệ của d
            private bool IsValidD(int e, int d, int z)
            {
                return (e * d) % z == 1;
            }


            // Tính toán ước số chung lớn nhất (GCD) của e và z 
            private int GCD(int a, int b)
            {
                while (b != 0)
                {
                    int temp = b;
                    b = a % b;
                    a = temp;
                }
                return a;
            }

            // Mã hóa khóa K bằng công thức c =  k^e mod n
            public int Encrypt(int k)
            {
                return ModExp(k, e, n);
            }

            // Giải mã khóa K bằng công thức k =  c^d mod n
            public int Decrypt(int c)
            {
                return ModExp(c, d, n);
            }

            // Tính toán c = k^e mod n và  k = c^d mod n
            private int ModExp(int baseVal, int exp, int mod)
            {
                int result = 1;
                while (exp > 0)
                {
                    if ((exp % 2) == 1)
                    {
                        result = (result * baseVal) % mod;
                    }
                    baseVal = (baseVal * baseVal) % mod;
                    exp /= 2;
                }
                return result;
            }
        }
        // Mã hóa đối xứng CaeserCipher
        public class CaesarCipher
        {
            // Khóa K của mã hóa CaeserCipher
            public int Key { get; set; } 

            public CaesarCipher(int key)
            {
                Key = key;
            }
            // Mã hóa Plaintext bằng CaeserCipher
            public string Encrypt(string plainText)
            {
                StringBuilder encryptedText = new StringBuilder();
                foreach (char ch in plainText)
                {
                    // Nếu là chứ cái thì thay đổi thành ký tự tương ứng , ngược lại là số thì không thay đổi 
                    if (char.IsLetter(ch))
                    {
                        char d = char.IsUpper(ch) ? 'A' : 'a';
                        int newIndex = (((ch - d) + Key) % 26);
                        encryptedText.Append((char)(newIndex + d));
                    }
                    else
                    {
                        encryptedText.Append(ch);
                    }
                }
                return encryptedText.ToString();
            }
            // Giải mã Plaintext bằng CaeserCipher
            public string Decrypt(string cipherText)
            {
                StringBuilder decryptedText = new StringBuilder();

                // Nếu là chứ cái thì thay đổi thành ký tự tương ứng , ngược lại là số thì không thay đổi 
                foreach (char ch in cipherText)
                {
                    if (char.IsLetter(ch))
                    {
                        char d = char.IsUpper(ch) ? 'A' : 'a';
                        int newIndex = (((ch - d) - Key + 26) % 26);
                        decryptedText.Append((char)(newIndex + d));
                    }
                    else
                    {
                        decryptedText.Append(ch);
                    }
                }
                return decryptedText.ToString();
            }
        }


        private void btnEncrypt_Click(object sender, EventArgs e)
        {
            // Lấy giá trị từ các trường dữ liệu
            int p = int.Parse(txtP.Text);
            int q = int.Parse(txtQ.Text);
            int eValue = int.Parse(txtE.Text);
            int dValue = int.Parse(txtD.Text);
            int symmetricKey = int.Parse(txtSymmetricKey.Text);
            string plainText = txtPlainText.Text;

            // Khởi tạo thuật toán RSA 
            RSA rsa = new RSA(p, q, eValue, dValue);


            // Hiển thị giá trị n, z, d, khóa công khai (n, e) và khóa riêng tư (n, d) sau khi tính toán 
            txtN.Text = rsa.n.ToString(); 
            txtZ.Text = rsa.z.ToString(); 
            txtD.Text = rsa.d.ToString(); 
            txtPublicKey.Text = $"({rsa.n}, {rsa.e})"; 
            txtPrivateKey.Text = $"({rsa.n}, {rsa.d})"; 


            // Mã hóa thông điệp bằng Caesar cipher
            CaesarCipher caesar = new CaesarCipher(symmetricKey);
            string encryptedText = caesar.Encrypt(plainText);

            // Mã hóa khóa đối xứng bằng RSA
            int encryptedSymmetricKey = rsa.Encrypt(symmetricKey);

            // Hiển thị kết quả mã hóa
            txtEncryptedText.Text = encryptedText; // Hiển thị thông điệp đã mã hóa
            txtEncryptedKey.Text = encryptedSymmetricKey.ToString(); // Hiển thị khóa đối xứng đã mã hóa

        }

        private void btnDecrypt_Click(object sender, EventArgs e)
        {
            // Lấy giá trị từ các trường dữ liệu
            int p = int.Parse(txtP.Text);
            int q = int.Parse(txtQ.Text);
            int dValue = int.Parse(txtD.Text);
            int eValue = int.Parse(txtE.Text);
            int encryptedSymmetricKey = int.Parse(txtEncryptedKey.Text); // Lấy khóa đối xứng đã mã hóa
            string encryptedText = txtEncryptedText.Text; // Lấy thông điệp đã mã hóa

            // Khởi tạo thuật toán RSA
            RSA rsa = new RSA(p, q,eValue, dValue);
           

            // Hiển thị giá trị n, z, d, khóa công khai (n, e) và khóa riêng tư (n, d) sau khi tính toán 
            txtN.Text = rsa.n.ToString(); 
            txtZ.Text = rsa.z.ToString(); 
            txtD.Text = rsa.d.ToString(); 
            txtPublicKey.Text = $"({rsa.n}, {rsa.e})"; 
            txtPrivateKey.Text = $"({rsa.n}, {rsa.d})"; 


            // Giải mã khóa đối xứng
            int decryptedSymmetricKey = rsa.Decrypt(encryptedSymmetricKey);

            // Sử dụng khóa đối xứng để giải mã thông điệp
            CaesarCipher caesar = new CaesarCipher(decryptedSymmetricKey);
            string decryptedText = caesar.Decrypt(encryptedText);

            // Hiển thị thông điệp đã giải mã
            txtDecryptedData.Text = decryptedText;

        }


    }
}

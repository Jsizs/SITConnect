using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Drawing;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace AS_PracAssignment
{
    public partial class ChangePassword : System.Web.UI.Page
    {
        string MYDBConnectionString = System.Configuration.ConfigurationManager.ConnectionStrings["MYDBConnection"].ConnectionString;
        static string finalHash;
        static string salt;
        byte[] Key;
        byte[] IV;

        protected void Page_Load(object sender, EventArgs e)
        {

        }

        protected void btnPwdChg_Click(object sender, EventArgs e)
        {
            string pwd = tb_currentPwd.Text.ToString().Trim();
            string userid = tb_email.Text.ToString().Trim();
            string newPwd = tb_newPwd.Text.ToString().Trim();
            SHA512Managed hashingCheck = new SHA512Managed();
            string dbHash = getDBHash(userid);
            string dbSalt = getDBSalt(userid);

            try
            {
                if (dbSalt != null && dbSalt.Length > 0 && dbHash != null && dbHash.Length > 0)
                {
                    string pwdWithSaltCheck = pwd + dbSalt;
                    byte[] hashWithSaltCheck = hashingCheck.ComputeHash(Encoding.UTF8.GetBytes(pwdWithSaltCheck));
                    string userHash = Convert.ToBase64String(hashWithSaltCheck);

                    if (String.IsNullOrEmpty(getTimeOfPwdChange(userid)) == true) 
                    {
                        if (userHash.Equals(dbHash))
                        {
                            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
                            byte[] saltByte = new byte[8];

                            rng.GetBytes(saltByte);
                            salt = Convert.ToBase64String(saltByte);
                            SHA512Managed hashing = new SHA512Managed();
                            string pwdWithSalt = newPwd + salt;
                            byte[] plainHash = hashing.ComputeHash(Encoding.UTF8.GetBytes(newPwd));
                            byte[] hashWithSalt = hashing.ComputeHash(Encoding.UTF8.GetBytes(pwdWithSalt));
                            finalHash = Convert.ToBase64String(hashWithSalt);
                            RijndaelManaged cipher = new RijndaelManaged();
                            cipher.GenerateKey();
                            Key = cipher.Key;
                            IV = cipher.IV;

                            int noCheck = checkPassword(tb_newPwd.Text.ToString());

                            if (noCheck < 5)
                            {
                                errorMsg.Text = "Password is too weak. Please use a different password";
                                errorMsg.ForeColor = Color.Red;
                            }
                            else
                            {
                                updatePassword(userid, finalHash, salt);
                                updateTimeOfPwdChange(userid, DateTime.Now.ToString());
                                errorMsg.Text = "";
                                Response.Redirect("HomePage.aspx");
                            }

                        }
                        else
                        {
                            errorMsg.ForeColor = Color.Red;
                            errorMsg.Text = "Current password entered is wrong. Please try again.";
                            tb_currentPwd.Text = "";
                            tb_email.Text = "";
                            tb_newPwd.Text = "";
                        }
                    }
                    else
                    {
                        var checkTime = (DateTime.Now - Convert.ToDateTime(getTimeOfPwdChange(userid))).TotalMinutes;

                        if (checkTime >= 5)
                        {
                            if (userHash.Equals(dbHash))
                            {
                                RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
                                byte[] saltByte = new byte[8];

                                rng.GetBytes(saltByte);
                                salt = Convert.ToBase64String(saltByte);
                                SHA512Managed hashing = new SHA512Managed();
                                string pwdWithSalt = newPwd + salt;
                                byte[] plainHash = hashing.ComputeHash(Encoding.UTF8.GetBytes(newPwd));
                                byte[] hashWithSalt = hashing.ComputeHash(Encoding.UTF8.GetBytes(pwdWithSalt));
                                finalHash = Convert.ToBase64String(hashWithSalt);
                                RijndaelManaged cipher = new RijndaelManaged();
                                cipher.GenerateKey();
                                Key = cipher.Key;
                                IV = cipher.IV;

                                int noCheck = checkPassword(tb_newPwd.Text.ToString());

                                if (noCheck < 5)
                                {
                                    errorMsg.Text = "Password is too weak. Please use a different password";
                                    errorMsg.ForeColor = Color.Red;
                                }
                                else
                                {
                                    updatePassword(userid, finalHash, salt);
                                    updateTimeOfPwdChange(userid, DateTime.Now.ToString());
                                    errorMsg.ForeColor = Color.Green;
                                    errorMsg.Text = "Password has been updated!";                                    
                                }

                            }
                            else
                            {
                                errorMsg.ForeColor = Color.Red;
                                errorMsg.Text = "Current password entered is wrong. Please try again.";
                                tb_currentPwd.Text = "";
                                tb_email.Text = "";
                                tb_newPwd.Text = "";
                            }
                        }
                        else
                        {
                            errorMsg.ForeColor = Color.Red;
                            errorMsg.Text = "Cannot change password too quickly! Please wait 5 minutes";
                        }

                    }                   

                }
            }
            catch (Exception ex)
            {
                throw new Exception(ex.ToString());
            }
            finally { }
        }

        protected string getTimeOfPwdChange(string email)
        {
            string time = null;
            SqlConnection connection = new SqlConnection(MYDBConnectionString);
            string sql = "select TimeOfPwdChange FROM Account WHERE Email=@Email";
            SqlCommand command = new SqlCommand(sql, connection);
            command.Parameters.AddWithValue("@Email", email);
            try
            {
                connection.Open();
                using (SqlDataReader reader = command.ExecuteReader())
                {

                    while (reader.Read())
                    {
                        if (reader["TimeOfPwdChange"] != null)
                        {
                            if (reader["TimeOfPwdChange"] != DBNull.Value)
                            {
                                time = reader["TimeOfPwdChange"].ToString();
                            }
                        }
                    }

                }
            }
            catch (Exception ex)
            {
                throw new Exception(ex.ToString());
            }
            finally { connection.Close(); }
            return time;
        }

        protected void updateTimeOfPwdChange(string email, string time)
        {
            try
            {
                using (SqlConnection con = new SqlConnection(MYDBConnectionString))
                {
                    using (SqlCommand cmd = new SqlCommand("UPDATE Account SET TimeOfPwdChange = @TimeOfPwdChange where Email = @Email"))
                    {
                        using (SqlDataAdapter sda = new SqlDataAdapter())
                        {
                            cmd.CommandType = CommandType.Text;
                            cmd.Parameters.AddWithValue("@Email", email);
                            cmd.Parameters.AddWithValue("@TimeOfPwdChange", time);
                            cmd.Connection = con;
                            con.Open();
                            cmd.ExecuteNonQuery();
                            con.Close();
                        }
                    }
                }

            }
            catch (Exception ex)
            {
                throw new Exception(ex.ToString());
            }
        }

        protected void updatePassword(string email, string passwordHash, string passwordSalt)
        {
            try
            {
                using (SqlConnection con = new SqlConnection(MYDBConnectionString))
                {
                    using (SqlCommand cmd = new SqlCommand("UPDATE Account SET PasswordHash = @PasswordHash, PasswordSalt = @PasswordSalt where Email = @Email"))
                    {
                        using (SqlDataAdapter sda = new SqlDataAdapter())
                        {
                            cmd.CommandType = CommandType.Text;
                            cmd.Parameters.AddWithValue("@Email", email);
                            cmd.Parameters.AddWithValue("@PasswordHash", passwordHash);
                            cmd.Parameters.AddWithValue("@PasswordSalt", passwordSalt);
                            cmd.Connection = con;
                            con.Open();
                            cmd.ExecuteNonQuery();
                            con.Close();
                        }
                    }
                }

            }
            catch (Exception ex)
            {
                throw new Exception(ex.ToString());
            }
        }

        protected string getDBHash(string userid)
        {
            string h = null;
            SqlConnection connection = new SqlConnection(MYDBConnectionString);
            string sql = "select PasswordHash FROM Account WHERE Email=@USERID";
            SqlCommand command = new SqlCommand(sql, connection);
            command.Parameters.AddWithValue("@USERID", userid);
            try
            {
                connection.Open();
                using (SqlDataReader reader = command.ExecuteReader())
                {

                    while (reader.Read())
                    {
                        if (reader["PasswordHash"] != null)
                        {
                            if (reader["PasswordHash"] != DBNull.Value)
                            {
                                h = reader["PasswordHash"].ToString();
                            }
                        }
                    }

                }
            }
            catch (Exception ex)
            {
                throw new Exception(ex.ToString());
            }
            finally { connection.Close(); }
            return h;
        }

        protected string getDBSalt(string userid)
        {
            string s = null;
            SqlConnection connection = new SqlConnection(MYDBConnectionString);
            string sql = "select PASSWORDSALT FROM ACCOUNT WHERE Email=@USERID";
            SqlCommand command = new SqlCommand(sql, connection);
            command.Parameters.AddWithValue("@USERID", userid);
            try
            {
                connection.Open();
                using (SqlDataReader reader = command.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        if (reader["PASSWORDSALT"] != null)
                        {
                            if (reader["PASSWORDSALT"] != DBNull.Value)
                            {
                                s = reader["PASSWORDSALT"].ToString();
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception(ex.ToString());
            }
            finally { connection.Close(); }
            return s;
        }

        protected byte[] encryptData(string data)
        {
            byte[] cipherText = null;
            try
            {
                RijndaelManaged cipher = new RijndaelManaged();
                cipher.IV = IV;
                cipher.Key = Key;
                ICryptoTransform encryptTransform = cipher.CreateEncryptor();
                //ICryptoTransform decryptTransform = cipher.CreateDecryptor();
                byte[] plainText = Encoding.UTF8.GetBytes(data);
                cipherText = encryptTransform.TransformFinalBlock(plainText, 0, plainText.Length);
            }
            catch (Exception ex)
            {
                throw new Exception(ex.ToString());
            }
            finally { }
            return cipherText;
        }

        private int checkPassword(string password)
        {
            int score = 0;

            //Score 1 very weak!
            //if length of password is less than 8 chars
            if (password.Length < 8)
            {
                return 1;
            }
            else
            {
                score = 1;
            }

            //Score 2 weak
            if (Regex.IsMatch(password, "[a-z]"))
            {
                score++;
            }

            //Score 3 medium
            if (Regex.IsMatch(password, "[A-Z]"))
            {
                score++;
            }

            //Score 4 strong
            if (Regex.IsMatch(password, "[0-9]"))
            {
                score++;
            }

            //Score 5 excellent
            if (Regex.IsMatch(password, "^[a-zA-Z0-9 ]*$"))
            {
                return score;
            }
            else
            {
                score++;
            }


            return score;
        }

        protected void btnBack_Click(object sender, EventArgs e)
        {
            Response.Redirect("HomePage.aspx");
        }
    }
}
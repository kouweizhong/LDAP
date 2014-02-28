using System;
using System.Collections;
using System.Collections.Generic;
using System.DirectoryServices;

namespace LDAP
{
    /// <summary>
    /// Provides methods for interacting with a directory via LDAP.
    /// </summary>
    public class LDAP
    {
        private string m_ldapPath;
        private string m_userName;
        private string m_password;

        #region Constructors
        /// <summary>
        /// Creates a new LDAP object using the specified path. The calling 
        /// process is assumed to have rights to read from and write to the 
        /// directory.
        /// </summary>
        /// <param name="ldapPath"></param>
        public LDAP(string ldapPath)
        {
            m_ldapPath = ldapPath;
        }

        /// <summary>
        /// Creates a new LDAP object using the specified path and credentials.
        /// </summary>
        /// <param name="ldapPath"></param>
        /// <param name="userName"></param>
        /// <param name="password"></param>
        public LDAP(string ldapPath, string userName, string password)
        {
            m_ldapPath = ldapPath;
            m_userName = userName;
            m_password = password;
        }
        #endregion

        #region Methods
        /// <summary>
        /// Authenticates a user against a directory.
        /// </summary>
        /// <param name="userName">User account being authenticated.</param>
        /// <param name="password">User password.</param>
        /// <param name="getAddlInfo">Indicates additional account information should be retrieved upon a successful authentication.</param>
        public LDAPResult Authenticate(string userName, string password, bool getAddlInfo = false)
        {
            Object obj = null;
            DirectoryEntry de = null;
            DirectorySearcher deSearcher = null;
            SearchResult searchResult;
            LDAPResult result = new LDAPResult();
            List<string> groups = null;

            try
            {
                de = new DirectoryEntry(m_ldapPath, userName, password);

                // Bind to the native AdsObject to force authentication
                obj = de.NativeObject;

                deSearcher = new DirectorySearcher(de);
                deSearcher.Filter = "(SAMAccountName=" + userName + ")";
                deSearcher.PropertiesToLoad.Add("cn");

                if (getAddlInfo)
                {
                    deSearcher.PropertiesToLoad.Add("MemberOf");
                    deSearcher.PropertiesToLoad.Add("mail");
                    deSearcher.PropertiesToLoad.Add("department");
                    deSearcher.PropertiesToLoad.Add("telephoneNumber");
                }

                searchResult = deSearcher.FindOne();

                if (searchResult == null)
                {
                    result.ResultCode = 1;
                    result.ErrorMessage = "Authentication failed.";
                    result.Process = "Authenticate";
                }
                else
                {
                    result.UserObject = new LDAPUserObject();
                    result.UserObject.DisplayName = searchResult.Properties["cn"][0].ToString();

                    if (getAddlInfo)
                    {
                        if (searchResult.Properties["mail"].Count > 0)
                        {
                            result.UserObject.EmailAddress = searchResult.Properties["mail"][0].ToString();
                        }
                        if (searchResult.Properties["department"].Count > 0)
                        {
                            result.UserObject.Department = searchResult.Properties["department"][0].ToString();
                        }
                        if (searchResult.Properties["telephoneNumber"].Count > 0)
                        {
                            result.UserObject.PhoneNumber = searchResult.Properties["telephoneNumber"][0].ToString();
                        }

                        result.UserObject.MailingAddress = GetUserAddress(userName);
                        groups = new List<string>();

                        if (searchResult.Properties["MemberOf"] != null)
                        {
                            foreach (object o in searchResult.Properties["MemberOf"])
                            {
                                groups.Add(TrimToName((string) o));
                            }
                        }

                        result.UserObject.Groups = groups;
                    }
                }

                return result;
            }
            catch (Exception ex)
            {
                result.ResultCode = 1;
                result.ErrorMessage = ex.Message.Trim();
                result.FullErrorMessage = ex.ToString().Trim();
                result.Source = ex.Source.Trim();
                result.Process = "Authenticate";

                return result;
            }
            finally
            {
                if (de != null)
                {
                    de.Dispose();
                }
                if (deSearcher != null)
                {
                    deSearcher.Dispose();
                }
            }
        }

        public IEnumerable<string> GetUserGroupMembership(string userName)
        {
            List<string> results = null;
            List<string> groups = null;
            List<string> subGroups = null;
            string filter = null;

            filter = "(&(objectCategory=person)(samAccountName=" + userName + "))";
            results = Search(filter, "MemberOf");
            groups = new List<string>();

            if (results != null)
            {
                foreach (string result in results)
                {
                    groups.Add(result);
                    subGroups = GetGroupMembershipByGroup(result);

                    foreach (string subGroup in subGroups)
                    {
                        if (!groups.Contains(subGroup))
                        {
                            groups.Add(subGroup);
                        }
                    }
                }
            }

            return groups;
        }

        public IEnumerable<string> GetLocalGroupMembership(string userToCheck)
        {
            object colGroups;
            List<string> groups = null;

            using (DirectoryEntry deComputer = GetDirectoryEntry())
            {
                using (DirectoryEntry deUser = deComputer.Children.Find(userToCheck))
                {
                    colGroups = deUser.Invoke("Groups");
                    groups = new List<string>();

                    foreach (object o in (IEnumerable)colGroups)
                    {
                        using (DirectoryEntry d = new DirectoryEntry(o))
                        {
                            groups.Add(d.Name);
                        }
                    }

                    return groups;
                }
            }
        }

        public IEnumerable<string> GetGroups()
        {
            List<string> groups = null;
            string filter = null;

            filter = "(&(objectClass=group))";
            groups = Search(filter);
            groups.Sort();

            return groups;
        }

        public IEnumerable<LDAPUserObject> GetUsers(string filter = "")
        {
	        List<LDAPUserObject> users = null;
	        LDAPUserObject ldapUser;

            using (DirectoryEntry de = GetDirectoryEntry())
            {
                using (DirectorySearcher deSearcher = new DirectorySearcher(de))
                {
		            if (string.IsNullOrEmpty(filter)) {
			            deSearcher.Filter = "(&(objectCategory=person))";
		            } else {
			            deSearcher.Filter = filter;
		            }

		            deSearcher.PropertiesToLoad.Add("samAccountName");
		            deSearcher.PropertiesToLoad.Add("displayName");

                    using (SearchResultCollection results = deSearcher.FindAll())
                    {
		                users = new List<LDAPUserObject>();

		                foreach (SearchResult result in results) {
			                ldapUser = new LDAPUserObject();
			                ldapUser.UserName = result.Properties["samAccountName"][0].ToString();

			                if (result.Properties["displayName"].Count > 0) {
				                ldapUser.DisplayName = result.Properties["displayName"][0].ToString();
			                }

			                users.Add(ldapUser);
		                }

		                users.Sort(CompareLDAPUsers);
		                return users;
                    }
                }
            }
        }

        public MailingAddress GetUserAddress(string userName)
        {
            MailingAddress mailingAddr;
            string strAddr;
            int crlfIndex = 0;

            mailingAddr = new MailingAddress();
            strAddr = GetUserProperty(userName, "streetAddress");
            crlfIndex = strAddr.IndexOf(Environment.NewLine);

            if (crlfIndex == -1)
            {
                mailingAddr.StreetLine1 = strAddr;
            }
            else
            {
                mailingAddr.StreetLine1 = strAddr.Substring(0, crlfIndex);
                mailingAddr.StreetLine2 = strAddr.Substring(crlfIndex + 2, strAddr.Length - crlfIndex - 2);
            }

            mailingAddr.POBox = GetUserProperty(userName, "postOfficeBox");
            mailingAddr.City = GetUserProperty(userName, "l");
            mailingAddr.State = GetUserProperty(userName, "st");
            mailingAddr.PostalCode = GetUserProperty(userName, "postalCode");
            mailingAddr.Country = GetUserProperty(userName, "c");

            return mailingAddr;
        }

        public string GetUserEmailAddress(string userName)
        {
            return GetUserProperty(userName, "mail");
        }

        public string GetUserCompany(string userName)
        {
            return GetUserProperty(userName, "company");
        }

        public string GetUserDisplayName(string userName)
        {
            return GetUserProperty(userName, "displayName");
        }

        public string GetUserDepartment(string userName)
        {
            return GetUserProperty(userName, "department");
        }

        public string GetUserPhoneNumber(string userName)
        {
            return GetUserProperty(userName, "telephoneNumber");
        }

        public DateTime GetPasswordLastChanged(string userName)
        {
            long fileTime = 0;

            fileTime = Convert.ToInt64(GetUserProperty(userName, "pwdLastSet"));
            return DateTime.FromFileTime(fileTime);
        }

        public bool UserExists(string userName)
        {
            List<string> results = null;
            string filter = null;

            filter = "(&(objectCategory=person)(samAccountName=" + userName + "))";
            results = Search(filter);

            if (results.Count > 0)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        public string GetUserNameByEmail(string emailAddr)
        {
            string filter = null;
            string userName = "";
            string emailUserName = null;
            List<string> results = null;

            filter = "(&(objectCategory=person)(mail=" + emailAddr + "))";
            results = Search(filter);

            if (results.Count > 0)
            {
                userName = results[0];
            }

            // If the account couldn't be found, possibly because the e-mail attribute 
            // is blank, see if the user name portion of the e-mail address matches an 
            // existing account
            emailUserName = emailAddr.Substring(0, emailAddr.IndexOf("@"));
            filter = "(&(objectCategory=person)(samAccountName=" + emailUserName + "))";
            results = Search(filter);

            if (results.Count > 0)
            {
                userName = results[0];
            }

            return userName;
        }

        public void ChangePassword(string userName, string password)
        {
            using (DirectoryEntry de = GetDirectoryEntryForUser(userName))
            {
                de.Invoke("SetPassword", new object[] { password });

                // Unlock the account in case it was locked after too many failed login
                // attempts
                de.Properties["lockoutTime"].Value = 0;

                de.CommitChanges();
                de.Close();
            }
        }
        #endregion

        #region Directory maintenance methods
        /// <summary>
        /// Finds all active user accounts whose 'physicalDeliveryOfficeName' property is blank.
        /// </summary>
        /// <returns></returns>
        public IEnumerable<LDAPUserObject> GetUsersWithMissingOffice()
        {
            return GetUsersWithMissingProperty("(&(objectCategory=person)(!physicalDeliveryOfficeName=*)(!userAccountControl:1.2.840.113556.1.4.803:=2))");
        }

        /// <summary>
        /// Finds all active user accounts whose 'telephoneNumber' property is blank.
        /// </summary>
        /// <returns></returns>
        public IEnumerable<LDAPUserObject> GetUsersWithMissingPhoneNumber()
        {
            return GetUsersWithMissingProperty("(&(objectCategory=person)(!telephoneNumber=*)(!userAccountControl:1.2.840.113556.1.4.803:=2))");
        }

        /// <summary>
        /// Finds all active user accounts whose 'mail' property is blank.
        /// </summary>
        /// <returns></returns>
        public IEnumerable<LDAPUserObject> GetUsersWithMissingEmailAddress()
        {
            return GetUsersWithMissingProperty("(&(objectCategory=person)(!mail=*)(!userAccountControl:1.2.840.113556.1.4.803:=2))");
        }

        /// <summary>
        /// Finds all active user accounts whose 'streetAddress' property is blank.
        /// </summary>
        /// <returns></returns>
        public IEnumerable<LDAPUserObject> GetUsersWithMissingAddress()
        {
            return GetUsersWithMissingProperty("(&(objectCategory=person)(!streetAddress=*)(!userAccountControl:1.2.840.113556.1.4.803:=2))");
        }

        /// <summary>
        /// Finds all active user accounts whose 'department' property is blank.
        /// </summary>
        /// <returns></returns>
        public IEnumerable<LDAPUserObject> GetUsersWithMissingDepartment()
        {
            return GetUsersWithMissingProperty("(&(objectCategory=person)(!department=*)(!userAccountControl:1.2.840.113556.1.4.803:=2))");
        }

        /// <summary>
        /// Returns a list of users and their password expiration date.
        /// </summary>
        /// <returns></returns>
        public IEnumerable<LDAPUserObject> GetUsersPasswordExpiration(string filter = "")
        {
            List<LDAPUserObject> users = null;
            LDAPUserObject ldapUser;

            using (DirectoryEntry de = GetDirectoryEntry())
            {
                using (DirectorySearcher deSearcher = new DirectorySearcher(de))
                {
                    if (filter == "")
                    {
                        deSearcher.Filter = "(&(objectCategory=person))";
                    }
                    else
                    {
                        deSearcher.Filter = filter;
                    }

                    deSearcher.PropertiesToLoad.Add("samAccountName");
                    deSearcher.PropertiesToLoad.Add("displayName");
                    deSearcher.PropertiesToLoad.Add("pwdLastSet");

                    using (SearchResultCollection results = deSearcher.FindAll())
                    {
                        users = new List<LDAPUserObject>();

                        foreach (SearchResult result in results)
                        {
                            ldapUser = new LDAPUserObject();
                            ldapUser.UserName = result.Properties["samAccountName"][0].ToString();
                            ldapUser.DisplayName = result.Properties["displayName"][0].ToString();
                            ldapUser.PasswordLastSet = DateTime.FromFileTime((long)result.Properties["pwdLastSet"][0]);
                            users.Add(ldapUser);
                        }

                        users.Sort(CompareLDAPUsers);
                        return users;
                    }
                }
            }
        }
        #endregion

        #region Private routines
        private List<string> GetGroupMembershipByGroup(string groupName)
        {
            List<string> results = null;
            List<string> groups = null;
            List<string> subGroups = null;
            string filter = null;

            filter = "(&(objectCategory=group)(cn=" + groupName + "))";
            results = Search(filter, "MemberOf");
            groups = new List<string>();

            if (results != null)
            {
                foreach (string result in results)
                {
                    // Skip any group whose name matches the one we are checking
                    // to avoid infinite recursion
                    if (result == groupName)
                    {
                        continue;
                    }

                    groups.Add(result);

                    subGroups = GetGroupMembershipByGroup(result);
                    foreach (string subGroup in subGroups)
                    {
                        if (!groups.Contains(subGroup))
                        {
                            groups.Add(subGroup);
                        }
                    }
                }
            }

            return groups;
        }

        private DirectoryEntry GetDirectoryEntry()
        {
            if (String.IsNullOrEmpty(m_userName))
            {
                return new DirectoryEntry(m_ldapPath);
            }
            else
            {
                return new DirectoryEntry(m_ldapPath, m_userName, m_password);
            }
        }

        private DirectoryEntry GetDirectoryEntryForUser(string userName)
        {
            SearchResult result = null;

            using (DirectoryEntry de = GetDirectoryEntry())
            {
                using (DirectorySearcher deSearcher = new DirectorySearcher(de))
                {
                    deSearcher.Filter = "(&(objectCategory=person)(samAccountName=" + userName + "))";
                    deSearcher.SearchScope = SearchScope.Subtree;
                    result = deSearcher.FindOne();

                    return result.GetDirectoryEntry();
                }
            }
        }

        private List<LDAPUserObject> GetUsersWithMissingProperty(string filter)
        {
            List<LDAPUserObject> users = null;

            using (DirectoryEntry de = GetDirectoryEntry())
            {
                using (DirectorySearcher deSearcher = new DirectorySearcher(de))
                {
                    deSearcher.Filter = filter;
                    deSearcher.PropertiesToLoad.Add("samAccountName");
                    deSearcher.PropertiesToLoad.Add("cn");

                    using (SearchResultCollection results = deSearcher.FindAll())
                    {
                        if (results == null)
                        {
                            return null;
                        }
                        else
                        {
                            users = new List<LDAPUserObject>();

                            foreach (SearchResult result in results)
                            {
                                users.Add(new LDAPUserObject(result.Properties["samAccountName"][0].ToString(), result.Properties["cn"][0].ToString()));
                            }

                            users.Sort(CompareLDAPUsers);
                            return users;
                        }
                    }
                }
            }
        }

        private List<string> Search(string filter, string targetProperty = "")
        {
            using (DirectoryEntry de = GetDirectoryEntry())
            {
                return RunSearch(de, filter, targetProperty);
            }
        }

        private List<string> RunSearch(DirectoryEntry de, string filter, string targetProperty = "")
        {
            List<string> searechResults = new List<string>();

            using (DirectorySearcher deSearcher = new DirectorySearcher(de))
            {
                deSearcher.Filter = filter;

                using (SearchResultCollection results = deSearcher.FindAll())
                {
                    foreach (SearchResult result in results)
                    {
                        if (string.IsNullOrEmpty(targetProperty))
                        {
                            // If no specific property is being sought, simply return 
                            // the common name
                            searechResults.Add(TrimToName(result.GetDirectoryEntry().Name));
                        }
                        else
                        {
                            foreach (object o in result.Properties[targetProperty])
                            {
                                searechResults.Add(TrimToName((string) o));
                            }
                        }
                    }

                }
            }

            return searechResults;
        }

        private string GetUserProperty(string userName, string propName)
        {
            DirectorySearcher deSearcher = null;
            DirectoryEntry de = null;
            SearchResult result = null;

            de = GetDirectoryEntry();
            deSearcher = new DirectorySearcher(de);
            deSearcher.Filter = "(&(objectCategory=person)(samAccountName=" + userName + "))";
            deSearcher.SearchScope = SearchScope.Subtree;
            result = deSearcher.FindOne();

            return TrimToName(result.Properties[propName][0].ToString());
        }

        private int CompareLDAPUsers(LDAPUserObject x, LDAPUserObject y)
        {
            if (x == null)
            {
                if (y == null)
                {
                    return 0;
                }
                else
                {
                    return -1;
                }
            }
            else
            {
                if (y == null)
                {
                    return 1;
                }
                else
                {
                    return string.Compare(x.DisplayName, y.DisplayName);
                }
            }
        }

        private string TrimToName(string path)
        {
            string[] parts = null;

            parts = path.Split(new char[] {','});
            return parts[0].Replace("CN=", string.Empty);
        }
        #endregion
    }
}

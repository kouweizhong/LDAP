using System;
using System.Collections.Generic;

namespace LDAP
{
    public class LDAPUserObject
    {
        public string UserName { get; set; }
        public string DisplayName { get; set; }
        public string EmailAddress { get; set; }
        public string Department { get; set; }
        public string PhoneNumber { get; set; }
        public DateTime? PasswordLastSet { get; set; }
        public MailingAddress MailingAddress { get; set; }

        /// <summary>
        /// List of groups that the given user is a member of.
        /// </summary>
        public IEnumerable<string> Groups { get; set; }

        public LDAPUserObject()
        {
        }

        public LDAPUserObject(string userName)
        {
            this.UserName = userName;
        }

        public LDAPUserObject(string userName, string displayName)
        {
            this.UserName = userName;
            this.DisplayName = displayName;
        }

        public override string ToString()
        {
            return this.DisplayName;
        }
    }
}

namespace LDAP
{
    public class LDAPResult
    {
        public int ResultCode { get; set; }
        public string ErrorMessage { get; set; }
        public string FullErrorMessage { get; set; }
        public string Source { get; set; }
        public string Process { get; set; }
        public string Tag { get; set; }
        public LDAPUserObject UserObject { get; set; }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Data;
using System.Windows;
using System.Collections.ObjectModel;

namespace BestPractices
{
    internal class RolesAndGroupsTabData
    {
        public ObservableCollection<RoleAndGroupMemberInfo> roleAndGroupMembership = new ObservableCollection<RoleAndGroupMemberInfo>();

        public RolesAndGroupsTabData() 
        {
            RoleAndGroupMemberInfo globalAdmin = new RoleAndGroupMemberInfo();
            globalAdmin.ID = "62e90394-69f5-4237-9190-012177145e10";
            globalAdmin.IsMember = string.Empty;
            globalAdmin.Name = "Global Admins";
            roleAndGroupMembership.Add(globalAdmin);

            RoleAndGroupMemberInfo globalReader = new RoleAndGroupMemberInfo();
            globalReader.ID = "f2ef992c-3afb-46b9-b7cf-a126ee74c451";
            globalReader.IsMember = string.Empty;
            globalReader.Name = "Global Readers";
            roleAndGroupMembership.Add(globalReader);

            RoleAndGroupMemberInfo groupAdmin = new RoleAndGroupMemberInfo();
            groupAdmin.ID = "fdd7a751-b60b-444a-984c-02652fe8fa1c";
            groupAdmin.IsMember = string.Empty;
            groupAdmin.Name = "Group Admins";
            roleAndGroupMembership.Add(groupAdmin);

            RoleAndGroupMemberInfo developer = new RoleAndGroupMemberInfo();
            developer.ID = "cf1c38e5-3621-4004-a7cb-879624dced7c";
            developer.IsMember = string.Empty;
            developer.Name = "App Developers";
            roleAndGroupMembership.Add(developer);
        }
    }

    public class RoleAndGroupMemberInfo
    {
        public string ID { get; set; }
        public string IsMember { get; set; }
        public string Name { get; set; }
    }

}

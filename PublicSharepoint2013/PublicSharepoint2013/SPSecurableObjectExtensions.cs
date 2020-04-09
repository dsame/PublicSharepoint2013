using System;
using System.Linq;
using Microsoft.SharePoint;

namespace PublicSharepoint2013
{
    /// <summary>
    /// Расширения для объектов таких безопасности, как: SPWeb, SPList, SPListItem
    /// </summary>
    public static class SPSecurableObjectExtensions
    {
        /// <summary>
        /// Проверить права пользователя/группы и выдать, если их нет, на объект путем назначения ролей, разорвав наследование, если необходимо.
        /// </summary>
        /// <param name="securableObject">SPWeb, SPList или SPListItem</param>
        /// <param name="principal">Пользователь или группа</param>
        /// <param name="rolesName">Отображаемые имена ролей, которые необходимо добавить. 
        /// Ролями являются: Совместная работа, Только чтение, Полный доступ и т.п.</param>
        /// <param name="breakRoleInheritance">Разорвать наследование, чтобы выдать права?</param>
        public static void GrantPermissions(this SPSecurableObject securableObject, SPPrincipal principal, string[] rolesName, bool breakRoleInheritance)
        {
            if (securableObject == null)
                throw new ArgumentNullException("securableObject");
            if (principal == null)
                throw new ArgumentNullException("principal");
            if (rolesName == null)
                throw new ArgumentNullException("rolesName");
            if (rolesName.Length == 0)
                throw new ArgumentException("roles can not be empty");
            
            // Если у объекта нет уникальных прав и нельзя их разорвать,
            // то ничего не делаем
            if (!securableObject.HasUniqueRoleAssignments)
                if (!breakRoleInheritance)
                    return;

            SPWeb web = principal.ParentWeb;

            // Определяем суммарные базовые права указанных ролей, которые необходимо предоставить
            SPBasePermissions rolesSummary = new SPBasePermissions();
            foreach (string roleName in rolesName)
            {
                SPRoleDefinition role = null;
                try
                {
                    role = web.RoleDefinitions[roleName];                    
                }
                catch (SPException ex)
                {
                    throw new SPException(string.Format("Не удалось обнаружить роль {0} на сайте {1}", roleName, web.Url), ex);
                }
                rolesSummary |= role.BasePermissions;
            }
            
            // Определяем базовые права на объект для указанного пользователя/группы
            SPBasePermissions permissionsInfo = SPBasePermissions.EmptyMask;
            if (principal is SPUser)
            {
                permissionsInfo = securableObject.GetUserEffectivePermissions(principal.LoginName);
            }
            else
            {
                // GetAssignmentByPrincipal кидает ArgumentException, если не найдено
                SPRoleAssignment ra = securableObject.RoleAssignments.Cast<SPRoleAssignment>()
                    .FirstOrDefault(roleAssignment =>
                        roleAssignment.Member.LoginName.Equals(principal.LoginName,
                            StringComparison.InvariantCultureIgnoreCase));
                if (ra != null)
                {
                    SPRoleDefinitionBindingCollection roles = ra.RoleDefinitionBindings;
                    foreach(SPRoleDefinition role in roles)
                    {
                        permissionsInfo |= role.BasePermissions;
                    }
                }
            }
            
            // Если имеющиеся права содержат выдаваемые, то ничего не делаем
            if ((rolesSummary & permissionsInfo) == rolesSummary)
                return;

            // Сбрасываем права
            securableObject.BreakRoleInheritance(true);
                        
            // Выдаем все роли одним назначением
            var assignment = new SPRoleAssignment(principal);

            foreach (string roleName in rolesName)
            {
                SPRoleDefinition role = null;
                try
                {
                    role = web.RoleDefinitions[roleName];                    
                }
                catch (SPException ex)
                {
                    throw new SPException(string.Format("Не удалось обнаружить роль {0} на сайте {1}", roleName, web.Url), ex);
                }
                assignment.RoleDefinitionBindings.Add(role);
            }
            
            securableObject.RoleAssignments.Add(assignment);
        }
    }
}
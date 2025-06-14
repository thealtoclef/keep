"use client";
import React, { useState, useEffect } from "react";
import { Tab, TabGroup, TabList, TabPanel, TabPanels } from "@tremor/react";
import {
  GlobeAltIcon,
  UserGroupIcon,
  EnvelopeIcon,
  KeyIcon,
  UsersIcon,
  ShieldCheckIcon,
  LockClosedIcon,
  PhotoIcon,
} from "@heroicons/react/24/outline";
import { MdOutlineSecurity } from "react-icons/md";
import { useHydratedSession as useSession } from "@/shared/lib/hooks/useHydratedSession";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useConfig } from "utils/hooks/useConfig";
import { AuthType } from "@/utils/authenticationType";

import Loading from "@/app/(keep)/loading";
import { EmptyStateTable } from "@/components/ui/EmptyStateTable";
import { EmptyStateImage } from "@/components/ui/EmptyStateImage";
import UsersTab from "./auth/users-tab";
import GroupsTab from "./auth/groups-tab";
import RolesTab from "./auth/roles-tab";
import APIKeysTab from "./auth/api-key-tab";
import SSOTab from "./auth/sso-tab";
import WebhookSettings from "./webhook-settings";
import SmtpSettings from "./smtp-settings";
import PermissionsTab from "./auth/permissions-tab";
import { PermissionsTable } from "./auth/permissions-table";

import { UsersTable } from "./auth/users-table";
import { GroupsTable } from "./auth/groups-table";
import { RolesTable } from "./auth/roles-table";
import { APIKeysTable } from "./auth/api-key-table";
import { User } from "@/app/(keep)/settings/models";
import ProviderImagesSettings from "./provider-images/provider-images-settings";

export default function SettingsPage() {
  const { data: session, status } = useSession();
  const router = useRouter();
  const searchParams = useSearchParams();
  const pathname = usePathname();
  const { data: configData } = useConfig();

  // TODO: refactor, we don't need to have so many states, we can just use the searchParams and derive the tabIndex and userSubTabIndex from it
  const [selectedTab, setSelectedTab] = useState<string>(
    searchParams?.get("selectedTab") || "users"
  );
  const [selectedUserSubTab, setSelectedUserSubTab] = useState<string>(
    searchParams?.get("userSubTab") || "users"
  );
  const [tabIndex, setTabIndex] = useState<number>(0);
  const [userSubTabIndex, setUserSubTabIndex] = useState<number>(0);

  const authType = configData?.AUTH_TYPE as AuthType;
  const docsUrl = configData?.KEEP_DOCS_URL || "https://docs.keephq.dev";

  // future: feature flags
  const usersAllowed = authType !== AuthType.NOAUTH;
  // azure, oauth, and noauth do not allow user creation
  const userCreationAllowed =
    authType !== AuthType.NOAUTH &&
    authType !== AuthType.AZUREAD &&
    authType !== AuthType.OAUTH;
  const rolesAllowed = authType !== AuthType.NOAUTH;
  const customRolesAllowed = authType === AuthType.KEYCLOAK;
  const ssoAllowed = authType === AuthType.KEYCLOAK;
  const groupsAllowed = authType === AuthType.KEYCLOAK;
  const permissionsAllowed = authType === AuthType.KEYCLOAK;
  const apiKeysAllowed = true; // Assuming API keys are always allowed

  useEffect(() => {
    const newSelectedTab = searchParams?.get("selectedTab") || "users";
    const newUserSubTab = searchParams?.get("userSubTab") || "users";
    const tabIndex =
      newSelectedTab === "users"
        ? 0
        : newSelectedTab === "webhook"
        ? 1
        : newSelectedTab === "smtp"
        ? 2
        : newSelectedTab === "provider-images"
        ? 3
        : 0;
    const userSubTabIndex =
      newUserSubTab === "users"
        ? 0
        : newUserSubTab === "groups"
        ? 1
        : newUserSubTab === "roles"
        ? 2
        : newUserSubTab === "permissions"
        ? 3
        : newUserSubTab === "api-keys"
        ? 4
        : newUserSubTab === "sso"
        ? 5
        : 0;
    setTabIndex(tabIndex);
    setUserSubTabIndex(userSubTabIndex);
    setSelectedTab(newSelectedTab);
    setSelectedUserSubTab(newUserSubTab);
  }, [searchParams]);

  const handleTabChange = (tab: string) => {
    router.replace(`${pathname}?selectedTab=${tab}`);
    setSelectedTab(tab);
  };

  const handleUserSubTabChange = (subTab: string) => {
    router.replace(`${pathname}?selectedTab=users&userSubTab=${subTab}`);
    setSelectedUserSubTab(subTab);
  };

  if (status === "loading") return <Loading />;
  if (status === "unauthenticated") router.push("/signin");

  const renderUserSubTabContent = (subTabName: string) => {
    switch (subTabName) {
      case "users":
        if (usersAllowed) {
          return (
            <UsersTab
              currentUser={session?.user}
              groupsAllowed={groupsAllowed}
              userCreationAllowed={userCreationAllowed}
            />
          );
        } else {
          const mockUsers: User[] = [
            {
              email: "john@example.com",
              name: "John Doe",
              role: "Admin",
              groups: [
                {
                  id: "1",
                  name: "Admins",
                  memberCount: 1,
                  members: ["john@example.com"],
                  roles: ["Admin"],
                },
              ],
              last_login: new Date().toISOString(),
              created_at: new Date().toISOString(),
            },
            {
              email: "jane@example.com",
              name: "Jane Smith",
              role: "User",
              groups: [
                {
                  id: "2",
                  name: "Users",
                  memberCount: 1,
                  members: ["jane@example.com"],
                  roles: ["User"],
                },
              ],
              last_login: new Date().toISOString(),
              created_at: new Date().toISOString(),
            },
          ];
          return (
            <EmptyStateTable
              message={`Users management is disabled. See documentation on how to enable it.`}
              documentationURL={`${docsUrl}/deployment/authentication/overview#authentication-features-comparison`}
              icon={UsersIcon}
            >
              <UsersTable
                users={mockUsers}
                currentUserEmail={session?.user?.email}
                authType={authType}
                isDisabled={true}
              />
            </EmptyStateTable>
          );
        }
      case "groups":
        if (groupsAllowed) {
          return <GroupsTab />;
        } else {
          const mockGroups = [
            {
              id: "1",
              name: "Admins",
              members: [
                "john@example.com",
                "doe@example.com",
                "keep@example.com",
                "noc@example.com",
              ],
              roles: ["Admin"],
            },
            {
              id: "2",
              name: "Operators",
              members: [
                "john@example.com",
                "doe@example.com",
                "keep@example.com",
                "noc@example.com",
              ],
              roles: ["Operator"],
            },
            {
              id: "3",
              name: "NOC",
              members: ["jane@example.com"],
              roles: ["NOC"],
            },
            {
              id: "4",
              name: "Managers",
              members: ["boss1@example.com", "boss2@example.com"],
              roles: ["Viewer"],
            },
          ];
          return (
            <EmptyStateTable
              icon={UserGroupIcon}
              message={`Groups management is disabled with. See documentation on how to enabled it.`}
              documentationURL={`${docsUrl}/deployment/authentication/overview#authentication-features-comparison`}
            >
              <GroupsTable
                groups={mockGroups}
                onRowClick={() => {}}
                onDeleteGroup={() => {}}
                isDisabled={true}
              />
            </EmptyStateTable>
          );
        }
      case "roles":
        if (rolesAllowed) {
          return <RolesTab customRolesAllowed={customRolesAllowed} />;
        } else {
          const mockRoles = [
            {
              id: "1",
              name: "Admin",
              description: "Full access",
              scopes: ["*"],
              predefined: true,
            },
            {
              id: "2",
              name: "User",
              description: "Limited access",
              scopes: ["read:*"],
              predefined: false,
            },
          ];
          return (
            <EmptyStateTable
              icon={ShieldCheckIcon}
              message={`Roles management is disabled with. See documentation on how to enabled it.`}
              documentationURL={`${docsUrl}/deployment/authentication/overview#authentication-features-comparison`}
            >
              <RolesTable
                roles={mockRoles}
                onRowClick={() => {}}
                onDeleteRole={() => {}}
                isDisabled={true}
              />
            </EmptyStateTable>
          );
        }
      case "permissions":
        if (permissionsAllowed) {
          return <PermissionsTab />;
        } else {
          const mockPresets = [
            {
              id: "1",
              name: "NOC Preset",
              type: "preset",
              assignments: ["user_noc@keephq.dev"],
            },
            {
              id: "2",
              name: "Dev Preset",
              type: "preset",
              assignments: ["user_noc@keephq.dev", "user_admin@keephq.dev"],
            },
            {
              id: "3",
              name: "QA Preset",
              type: "preset",
              assignments: ["user_noc@keephq.dev", "user_admin@keephq.dev"],
            },
            {
              id: "4",
              name: "Prod Preset",
              type: "preset",
              assignments: ["user_noc@keephq.dev", "user_admin@keephq.dev"],
            },
          ];
          return (
            <EmptyStateTable
              icon={MdOutlineSecurity}
              message={`Permissions management is disabled with. See documentation on how to enabled it.`}
              documentationURL={`${docsUrl}/deployment/authentication/overview#authentication-features-comparison`}
            >
              <PermissionsTable
                resources={mockPresets}
                onRowClick={() => {}}
                isDisabled={true}
              />
            </EmptyStateTable>
          );
        }
      case "api-keys":
        if (apiKeysAllowed) {
          return <APIKeysTab />;
        } else {
          const mockApiKeys = [
            {
              reference_id: "AdminKey",
              secret: "sk_test_abcdefghijklmnopqrstuvwxyz123456",
              role: "Admin",
              created_by: "john@example.com",
              created_at: "2023-05-01T12:00:00Z",
              last_used: "2023-06-15T15:30:00Z",
            },
            {
              reference_id: "ViewerKey",
              secret: "sk_test_zyxwvutsrqponmlkjihgfedcba654321",
              role: "Viewer",
              created_by: "jane@example.com",
              created_at: "2023-06-01T09:00:00Z",
              last_used: "2023-06-20T10:45:00Z",
            },
          ];
          return (
            <EmptyStateTable
              icon={KeyIcon}
              message={`API Keys management is disabled with. See documentation on how to enabled it.`}
              documentationURL={`${docsUrl}/deployment/authentication/overview#authentication-features-comparison`}
            >
              <APIKeysTable
                apiKeys={mockApiKeys}
                onRegenerate={() => {}}
                onDelete={() => {}}
                isDisabled={true}
              />
            </EmptyStateTable>
          );
        }
      case "sso":
        if (ssoAllowed) {
          return <SSOTab />;
        } else {
          return (
            <EmptyStateImage
              message={`SSO management is disabled with. See documentation on how to enabled it.`}
              documentationURL={`${docsUrl}/deployment/authentication/overview#authentication-features-comparison`}
              icon={LockClosedIcon}
              imageURL="/sso.png"
            />
          );
        }
      default:
        return null;
    }
  };

  return (
    <div className="flex flex-col h-full">
      <TabGroup index={tabIndex} className="flex-grow flex flex-col">
        <TabList>
          <Tab icon={UserGroupIcon} onClick={() => handleTabChange("users")}>
            Users and Access
          </Tab>
          <Tab icon={GlobeAltIcon} onClick={() => handleTabChange("webhook")}>
            Incoming Webhook
          </Tab>
          <Tab icon={EnvelopeIcon} onClick={() => handleTabChange("smtp")}>
            SMTP
          </Tab>
          <Tab
            icon={PhotoIcon}
            onClick={() => handleTabChange("provider-images")}
          >
            Provider Icons
          </Tab>
        </TabList>
        <TabPanels className="flex-grow overflow-hidden p-px">
          <TabPanel className="h-full">
            <TabGroup
              index={userSubTabIndex}
              className="h-full flex flex-col gap-4"
            >
              <TabList>
                <Tab
                  icon={UsersIcon}
                  onClick={() => handleUserSubTabChange("users")}
                >
                  Users
                </Tab>
                <Tab
                  icon={UserGroupIcon}
                  onClick={() => handleUserSubTabChange("groups")}
                >
                  Groups
                </Tab>
                <Tab
                  icon={ShieldCheckIcon}
                  onClick={() => handleUserSubTabChange("roles")}
                >
                  Roles
                </Tab>
                <Tab
                  icon={LockClosedIcon}
                  onClick={() => handleUserSubTabChange("permissions")}
                >
                  Permissions
                </Tab>
                <Tab
                  icon={KeyIcon}
                  onClick={() => handleUserSubTabChange("api-keys")}
                >
                  API Keys
                </Tab>
                <Tab
                  icon={MdOutlineSecurity}
                  onClick={() => handleUserSubTabChange("sso")}
                >
                  SSO
                </Tab>
              </TabList>
              <TabPanels className="flex-grow overflow-hidden p-px">
                <TabPanel className="h-full">
                  {renderUserSubTabContent("users")}
                </TabPanel>
                <TabPanel className="h-full">
                  {renderUserSubTabContent("groups")}
                </TabPanel>
                <TabPanel className="h-full">
                  {renderUserSubTabContent("roles")}
                </TabPanel>
                <TabPanel className="h-full">
                  {renderUserSubTabContent("permissions")}
                </TabPanel>
                <TabPanel className="h-full">
                  {renderUserSubTabContent("api-keys")}
                </TabPanel>
                <TabPanel className="h-full">
                  {renderUserSubTabContent("sso")}
                </TabPanel>
              </TabPanels>
            </TabGroup>
          </TabPanel>
          <TabPanel className="h-full pt-4">
            <WebhookSettings selectedTab={selectedTab} />
          </TabPanel>
          <TabPanel className="h-full pt-4">
            <SmtpSettings selectedTab={selectedTab} />
          </TabPanel>
          <TabPanel className="h-full pt-4">
            <ProviderImagesSettings />
          </TabPanel>
        </TabPanels>
      </TabGroup>
    </div>
  );
}

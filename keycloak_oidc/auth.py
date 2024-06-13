from django.contrib.auth.models import Group
from django.db import transaction
from mozilla_django_oidc import auth

CLAIMS_FIRST_NAME = "given_name"
CLAIMS_LAST_NAME = "family_name"
CLAIMS_REALM_ACCESS = "realm_access"
ROLES = "roles"


class OIDCAuthenticationBackend(auth.OIDCAuthenticationBackend):
    def save_user(self, user, claims):
        user.first_name = claims.get(CLAIMS_FIRST_NAME, "")
        user.last_name = claims.get(CLAIMS_LAST_NAME, "")
        user.save()

        self.update_groups(user, claims)

        return user

    def create_user(self, claims):
        user = super(OIDCAuthenticationBackend, self).create_user(claims)
        user = self.save_user(user, claims)
        return user

    def update_user(self, user, claims):
        user = self.save_user(user, claims)
        return user

    def clear_realm_access_groups(self, user):
        """
        Clears the user from the realm access groups
        """
        realm_access_groups = self.get_settings("OIDC_AUTHORIZED_GROUPS", None)
        assert (
            realm_access_groups
        ), "OIDC_AUTHORIZED_GROUPS access groups must be configured"

        for realm_access_group in realm_access_groups:
            group, _ = Group.objects.get_or_create(name=realm_access_group)
            group.user_set.remove(user)

    def update_groups(self, user, claims):
        """
        Transform roles obtained from keycloak into Django Groups and
        add them to the user. Note that any role not passed via keycloak
        will be removed from the user.
        """
        new_groups = set(claims.get(ROLES, []))
        current_groups = set(user.groups.values_list('name', flat=True))

        groups_to_add = new_groups - current_groups
        groups_to_remove = current_groups - new_groups

        with transaction.atomic():
            for group_name in groups_to_remove:
                group = Group.objects.get(name=group_name)
                group.user_set.remove(user)

            for group_name in groups_to_add:
                group, _ = Group.objects.get_or_create(name=group_name)
                group.user_set.add(user)

    def get_groups(self, access_info):
        realm_access = access_info.get(CLAIMS_REALM_ACCESS, {})
        groups = realm_access.get(ROLES, [])
        return groups

    def get_nonce(self, payload):
        if self.get_settings("OIDC_USE_NONCE", True):
            return payload.get("nonce")

        return None

    def get_userinfo(self, access_token, id_token, payload):
        """
        Get user details from the access_token and id_token and return
        them in a dict.
        """
        user_info = super().get_userinfo(access_token, id_token, payload)
        nonce = self.get_nonce(payload)
        access_info = self.verify_token(access_token, nonce=nonce)
        groups = self.get_groups(access_info)
        user_info[ROLES] = groups

        return user_info

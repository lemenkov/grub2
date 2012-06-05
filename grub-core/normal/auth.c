/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2009  Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <grub/auth.h>
#include <grub/list.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/env.h>
#include <grub/normal.h>
#include <grub/time.h>
#include <grub/i18n.h>
#include <grub/efi/api.h>
#include <grub/efi/efi.h>

struct grub_auth_user
{
  struct grub_auth_user *next;
  struct grub_auth_user **prev;
  char *name;
  grub_auth_callback_t callback;
  void *arg;
  int authenticated;
};

static struct grub_auth_user *users = NULL;

grub_err_t
grub_auth_register_authentication (const char *user,
				   grub_auth_callback_t callback,
				   void *arg)
{
  struct grub_auth_user *cur;

  cur = grub_named_list_find (GRUB_AS_NAMED_LIST (users), user);
  if (!cur)
    cur = grub_zalloc (sizeof (*cur));
  if (!cur)
    return grub_errno;
  cur->callback = callback;
  cur->arg = arg;
  if (! cur->name)
    {
      cur->name = grub_strdup (user);
      if (!cur->name)
	{
	  grub_free (cur);
	  return grub_errno;
	}
      grub_list_push (GRUB_AS_LIST_P (&users), GRUB_AS_LIST (cur));
    }
  return GRUB_ERR_NONE;
}

grub_err_t
grub_auth_unregister_authentication (const char *user)
{
  struct grub_auth_user *cur;
  cur = grub_named_list_find (GRUB_AS_NAMED_LIST (users), user);
  if (!cur)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "user '%s' not found", user);
  if (!cur->authenticated)
    {
      grub_free (cur->name);
      grub_list_remove (GRUB_AS_LIST (cur));
      grub_free (cur);
    }
  else
    {
      cur->callback = NULL;
      cur->arg = NULL;
    }
  return GRUB_ERR_NONE;
}

grub_err_t
grub_auth_authenticate (const char *user)
{
  struct grub_auth_user *cur;

  cur = grub_named_list_find (GRUB_AS_NAMED_LIST (users), user);
  if (!cur)
    cur = grub_zalloc (sizeof (*cur));
  if (!cur)
    return grub_errno;

  cur->authenticated = 1;

  if (! cur->name)
    {
      cur->name = grub_strdup (user);
      if (!cur->name)
	{
	  grub_free (cur);
	  return grub_errno;
	}
      grub_list_push (GRUB_AS_LIST_P (&users), GRUB_AS_LIST (cur));
    }

  return GRUB_ERR_NONE;
}

grub_err_t
grub_auth_deauthenticate (const char *user)
{
  struct grub_auth_user *cur;
  cur = grub_named_list_find (GRUB_AS_NAMED_LIST (users), user);
  if (!cur)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "user '%s' not found", user);
  if (!cur->callback)
    {
      grub_free (cur->name);
      grub_list_remove (GRUB_AS_LIST (cur));
      grub_free (cur);
    }
  else
    cur->authenticated = 0;
  return GRUB_ERR_NONE;
}

static int
is_authenticated (const char *userlist)
{
  const char *superusers;
  struct grub_auth_user *user;

  superusers = grub_env_get ("superusers");

  if (!superusers)
    return 1;

  FOR_LIST_ELEMENTS (user, users)
    {
      if (!(user->authenticated))
	continue;

      if ((userlist && grub_strword (userlist, user->name))
	  || grub_strword (superusers, user->name))
	return 1;
    }

  return 0;
}

static int
grub_username_get (char buf[], unsigned buf_size)
{
  unsigned cur_len = 0;
  int key;

  while (1)
    {
      key = grub_getkey (); 
      if (key == '\n' || key == '\r')
	break;

      if (key == '\e')
	{
	  cur_len = 0;
	  break;
	}

      if (key == '\b')
	{
	  cur_len--;
	  grub_printf ("\b");
	  continue;
	}

      if (!grub_isprint (key))
	continue;

      if (cur_len + 2 < buf_size)
	{
	  buf[cur_len++] = key;
	  grub_printf ("%c", key);
	}
    }

  grub_memset (buf + cur_len, 0, buf_size - cur_len);

  grub_xputs ("\n");
  grub_refresh ();

  return (key != '\e');
}

grub_err_t
grub_auth_secure_boot (void)
{
#ifdef GRUB_MACHINE_EFI
  grub_size_t datasize = 0;
  grub_uint8_t *data;
  grub_efi_guid_t guid = GRUB_EFI_GLOBAL_VARIABLE_GUID;
  unsigned int x;

  data = grub_efi_get_variable ("SecureBoot", &guid, &datasize);
  if (!data)
    return GRUB_ERR_NONE;

  for (x = 0; x < datasize; x++)
    if (data[x] == 1)
      return GRUB_ACCESS_DENIED;
#endif

  return GRUB_ERR_NONE;
}

int
grub_is_secure_boot (void)
{
  return grub_auth_secure_boot() == GRUB_ACCESS_DENIED;
}

#define SHIM_LOCK_GUID \
  { 0x605dab50, 0xe046, 0x4300, {0xab,0xb6,0x3d,0xd8,0x10,0xdd,0x8b,0x23} }

typedef grub_efi_status_t (*EFI_SHIM_LOCK_VERIFY)(void *buffer, grub_efi_uint32_t size);

typedef struct _SHIM_LOCK {
    EFI_SHIM_LOCK_VERIFY Verify;
} SHIM_LOCK;

grub_err_t
grub_auth_verify_signature (void *buffer, grub_uint32_t size)
{
#ifdef GRUB_MACHINE_EFI
  grub_efi_guid_t shim_guid = SHIM_LOCK_GUID;
  SHIM_LOCK *shim = NULL;
  grub_efi_handle_t *handles, shim_handle = NULL;
  grub_efi_uintn_t num_handles, i;
  grub_efi_status_t status;

  if (!grub_is_secure_boot())
    return GRUB_ERR_NONE;

  handles = grub_efi_locate_handle (GRUB_EFI_BY_PROTOCOL, &shim_guid, NULL,
				    &num_handles);
  if (!handles || num_handles == 0)
no_verify:
    return grub_error (GRUB_ACCESS_DENIED, "Could not find signature verification routine");

  for (i = 0; i < num_handles; i++)
    {
      shim_handle = handles[i];
      shim = grub_efi_open_protocol (shim_handle, &shim_guid,
				     GRUB_EFI_OPEN_PROTOCOL_GET_PROTOCOL);
      if (shim)
	break;
    }

  if (!shim)
    {
      grub_free(handles);
      goto no_verify;
    }

  status = shim->Verify(buffer, size);

  grub_free(handles);

  if (status == GRUB_EFI_SUCCESS)
    return GRUB_ERR_NONE;

  return grub_error (GRUB_ACCESS_DENIED, "Signature verification failed");
#else
  return GRUB_ERR_NONE;
#endif
}

grub_err_t
grub_auth_check_authentication (const char *userlist)
{
  char login[1024];
  struct grub_auth_user *cur = NULL;
  static unsigned long punishment_delay = 1;
  char entered[GRUB_AUTH_MAX_PASSLEN];
  struct grub_auth_user *user;

  grub_memset (login, 0, sizeof (login));

  if (is_authenticated (userlist))
    {
      punishment_delay = 1;
      return GRUB_ERR_NONE;
    }

  grub_puts_ (N_("Enter username: "));

  if (!grub_username_get (login, sizeof (login) - 1))
    goto access_denied;

  grub_puts_ (N_("Enter password: "));

  if (!grub_password_get (entered, GRUB_AUTH_MAX_PASSLEN))
    goto access_denied;

  FOR_LIST_ELEMENTS (user, users)
    {
      if (grub_strcmp (login, user->name) == 0)
	cur = user;
    }

  if (!cur || ! cur->callback)
    goto access_denied;

  cur->callback (login, entered, cur->arg);
  if (is_authenticated (userlist))
    {
      punishment_delay = 1;
      return GRUB_ERR_NONE;
    }

 access_denied:
  grub_sleep (punishment_delay);

  if (punishment_delay < GRUB_ULONG_MAX / 2)
    punishment_delay *= 2;

  return GRUB_ACCESS_DENIED;
}

static grub_err_t
grub_cmd_authenticate (struct grub_command *cmd __attribute__ ((unused)),
		       int argc, char **args)
{
  return grub_auth_check_authentication ((argc >= 1) ? args[0] : "");
}

static grub_command_t cmd;

void
grub_normal_auth_init (void)
{
  cmd = grub_register_command ("authenticate",
			       grub_cmd_authenticate,
			       N_("[USERLIST]"),
			       N_("Check whether user is in USERLIST."));

}

void
grub_normal_auth_fini (void)
{
  grub_unregister_command (cmd);
}

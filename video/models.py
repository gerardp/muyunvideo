# This is an auto-generated Django model module.
# You'll have to do the following manually to clean this up:
#     * Rearrange models' order
#     * Make sure each model has one field with primary_key=True
# Feel free to rename the models, but don't rename db_table values or field names.
#
# Also note: You'll have to insert the output of 'django-admin.py sqlcustom [appname]'
# into your database.

from django.db import models

class AuthGroup(models.Model):
    id = models.IntegerField(primary_key=True)
    name = models.CharField(max_length=240, unique=True)
    class Meta:
        db_table = u'auth_group'

class AuthGroupPermissions(models.Model):
    id = models.IntegerField(primary_key=True)
    group_id = models.IntegerField()
    permission_id = models.IntegerField()
    class Meta:
        db_table = u'auth_group_permissions'

class AuthPermission(models.Model):
    id = models.IntegerField(primary_key=True)
    name = models.CharField(max_length=150)
    content_type_id = models.IntegerField()
    codename = models.CharField(max_length=300, unique=True)
    class Meta:
        db_table = u'auth_permission'

class AuthUser(models.Model):
    id = models.IntegerField(primary_key=True)
    username = models.CharField(max_length=90, unique=True)
    first_name = models.CharField(max_length=90)
    last_name = models.CharField(max_length=90)
    email = models.CharField(max_length=225)
    password = models.CharField(max_length=384)
    is_staff = models.IntegerField()
    is_active = models.IntegerField()
    is_superuser = models.IntegerField()
    last_login = models.DateTimeField()
    date_joined = models.DateTimeField()
    class Meta:
        db_table = u'auth_user'

class AuthUserGroups(models.Model):
    id = models.IntegerField(primary_key=True)
    user_id = models.IntegerField()
    group_id = models.IntegerField()
    class Meta:
        db_table = u'auth_user_groups'

class AuthUserUserPermissions(models.Model):
    id = models.IntegerField(primary_key=True)
    user_id = models.IntegerField()
    permission_id = models.IntegerField()
    class Meta:
        db_table = u'auth_user_user_permissions'

class Contacts(models.Model):
    owner_id = models.IntegerField()
    is_favourite = models.IntegerField(null=True, blank=True)
    class Meta:
        db_table = u'contacts'

class DjangoAdminLog(models.Model):
    id = models.IntegerField(primary_key=True)
    action_time = models.DateTimeField()
    user_id = models.IntegerField()
    content_type_id = models.IntegerField(null=True, blank=True)
    object_id = models.TextField(blank=True)
    object_repr = models.CharField(max_length=600)
    action_flag = models.IntegerField()
    change_message = models.TextField()
    class Meta:
        db_table = u'django_admin_log'

class DjangoContentType(models.Model):
    id = models.IntegerField(primary_key=True)
    name = models.CharField(max_length=300)
    app_label = models.CharField(max_length=300, unique=True)
    model = models.CharField(max_length=300, unique=True)
    class Meta:
        db_table = u'django_content_type'

class DjangoSession(models.Model):
    session_key = models.CharField(max_length=120, primary_key=True)
    session_data = models.TextField()
    expire_date = models.DateTimeField()
    class Meta:
        db_table = u'django_session'

class DjangoSite(models.Model):
    id = models.IntegerField(primary_key=True)
    domain = models.CharField(max_length=300)
    name = models.CharField(max_length=150)
    class Meta:
        db_table = u'django_site'

class Interpreters(models.Model):
    uid = models.IntegerField(unique=True)
    name = models.CharField(max_length=93, unique=True, blank=True)
    language1_id = models.IntegerField()
    language2_id = models.IntegerField()
    class Meta:
        db_table = u'interpreters'

class Records(models.Model):
    uid = models.IntegerField(primary_key=True)
    caller_id = models.IntegerField()
    receiver_id = models.IntegerField()
    interpreter_id = models.IntegerField()
    start_time = models.DateTimeField(null=True, blank=True)
    end_time = models.DateTimeField(null=True, blank=True)
    class Meta:
        db_table = u'records'

class Users(models.Model):
    uid = models.IntegerField(unique=True)
    name = models.CharField(max_length=93, unique=True)
    accountcat_id = models.IntegerField()
    email = models.CharField(max_length=93, blank=True)
    loginpassword = models.CharField(max_length=120)
    paypassword = models.CharField(max_length=120)
    realname = models.CharField(max_length=45, blank=True)
    gender_id = models.IntegerField(null=True, blank=True)
    language_id = models.IntegerField()
    birthday = models.DateField(null=True, blank=True)
    mobile = models.CharField(max_length=45, blank=True)
    telephone = models.CharField(max_length=45, blank=True)
    introduce = models.TextField(blank=True)
    address = models.TextField(blank=True)
    postcode = models.CharField(max_length=18, blank=True)
    verifycode = models.CharField(max_length=60, blank=True)
    registertime = models.DateTimeField(null=True, blank=True)
    lastlogintime = models.DateTimeField(null=True, blank=True)
    class Meta:
        db_table = u'users'

class Sessions(models.Model):
    sender_id = models.IntegerField()
    receiver_id = models.IntegerField()
    interpreter_id = models.IntegerField()


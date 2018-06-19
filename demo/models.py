from django.db import models
from django.utils import timezone
from dateutil.relativedelta import relativedelta
from django.core.validators import RegexValidator
from django.utils.safestring import mark_safe
from django.conf import settings

identification_validator = RegexValidator(
    r'"(^[1|5]\d{11}$)|(^\d{2}-\d{4}-\d{4}$)"',
    message="Debe tener el formato 08-8888-8888 para nacionales o 500000000000 o 100000000000")


class PEMpresentation(object):

    def present(self, data):
        if type(data) == bytes:
            data = data.decode()
        return mark_safe("<pre>%s</pre>" % (data))

    def get_private_key_display(self):
        return self.present(self.private_key)

    def get_public_key_display(self):
        return self.present(self.public_key)

    def get_public_certificate_display(self):
        return self.present(self.public_certificate)

    def get_server_sign_key_display(self):
        return self.present(self.server_sign_key)

    def get_server_public_key_display(self):
        return self.present(self.server_public_key)


class Institution(models.Model, PEMpresentation):
    name = models.CharField(max_length=250)
    code = models.UUIDField()
    active = models.BooleanField(default=True)

    private_key = models.TextField()
    public_certificate = models.TextField()
    server_public_key = models.TextField()

    def __str__(self):
        return self.name

    class Meta:
        ordering = ('pk',)
        permissions = (
            ("view_institution", "Can see available tasks"),
        )


class NotificationURL(models.Model):
    description = models.CharField(max_length=250)
    url = models.URLField(null=True, blank=True)
    institution = models.ForeignKey(Institution)
    not_webapp = models.BooleanField(default=False)
    is_demo = models.BooleanField(default=False)

    def __str__(self):
        return "%s %s" % (
            self.institution,
            self.url or 'N/D'
        )

    class Meta:
        ordering = ('institution',)
        permissions = (
            ("view_notificationurl", "Can see available notification urls"),
        )


class Autenticar(models.Model):
    url = models.ForeignKey(NotificationURL, on_delete=models.CASCADE)


class AuthenticateDataRequest(models.Model):
    institution = models.ForeignKey(Institution)
    notification_url = models.URLField()
    identification = models.CharField(
        max_length=15, validators=[identification_validator],
        help_text="""'%Y-%m-%d %H:%M:%S',   es decir  '2006-10-25 14:30:59'""")
    # '%Y-%m-%d %H:%M:%S',   es decir  '2006-10-25 14:30:59'
    request_datetime = models.DateTimeField()
    code = models.CharField(max_length=20, default='N/D')

    STATUS = ((1, 'Solicitud recibida correctamente'),
              (2, 'Ha ocurrido algún problema al solicitar la firma'),
              (3, 'Solicitud con campos incompletos'),
              (4, 'Diferencia de hora no permitida entre cliente y servidor'),
              (5, 'La entidad no se encuentra registrada'),
              (6, 'La entidad se encuentra en estado inactiva'),
              (7, 'La URL no pertenece a la entidad solicitante'),
              (8, 'El tamaño de hash debe ser entre 1 y 130 caracteres'),
              (9, 'Algoritmo desconocido'),
              (10, 'Certificado incorrecto'))
    status = models.IntegerField(choices=STATUS, default=1)
    status_text = models.CharField(max_length=256, default='n/d')
    sign_document = models.TextField(null=True, blank=True)
    response_datetime = models.DateTimeField(auto_now=True)
    expiration_datetime = models.DateTimeField()
    id_transaction = models.IntegerField(default=0, db_index=True)
    duration = models.SmallIntegerField(default=3)
    received_notification = models.BooleanField(default=False)

    @property
    def left_time(self):
        now = timezone.now()
        ttime = relativedelta(self.expiration_datetime, now)
        return "%d:%d:%d" % (ttime.hours, ttime.minutes, ttime.seconds)

    class Meta:
        ordering = ('request_datetime',)
        permissions = (
            ("view_authenticatedatarequest",
             "Can see available Authenticate Data Request"),
        )

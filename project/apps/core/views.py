from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.views.generic import DetailView
from project.apps.core.models import User


@method_decorator(login_required, name='dispatch')
class ProfileDetail(DetailView):
    model = User
    template_name = 'profile.html'
    context_object_name = 'profile'

    def get_object(self):
        return self.request.user

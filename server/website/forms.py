from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms.validators import DataRequired


class ActivateForm(FlaskForm):
    user_code = StringField("user_code", validators=[DataRequired()])

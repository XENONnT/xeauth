
# -*- coding: utf-8 -*-

# DO NOT EDIT THIS FILE!
# This file has been autogenerated by dephell <3
# https://github.com/dephell/dephell

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


import os.path

readme = ''
here = os.path.abspath(os.path.dirname(__file__))
readme_path = os.path.join(here, 'README.rst')
if os.path.exists(readme_path):
    with open(readme_path, 'rb') as stream:
        readme = stream.read().decode('utf8')


setup(
    long_description=readme,
    name='xeauth',
    version='0.1.12',
    description='Top-level package for xeauth.',
    python_requires='<3.11,>=3.8',
    project_urls={"homepage": "https://github.com/jmosbacher/xeauth"},
    author='Yossi Mosbacher',
    author_email='joe.mosbacher@gmail.com',
    license='MIT',
    classifiers=['Development Status :: 2 - Pre-Alpha', 'Intended Audience :: Developers', 'License :: OSI Approved :: MIT License', 'Natural Language :: English', 'Programming Language :: Python :: 3.8'],
    entry_points={"console_scripts": ["xeauth = xeauth.cli:main"], "eve_panel.auth": ["XenonAuth = xeauth.integrations.eve_panel:XenonEveAuth"], "panel.auth": ["xeauth = xeauth.integrations.panel_server:XenonPanelAuth"]},
    packages=['xeauth', 'xeauth.integrations'],
    package_dir={"": "."},
    package_data={},
    install_requires=['appdirs==1.*,>=1.4.4', 'authlib==0.*,>=0.15.3', 'click', 'httpx==0.*,>=0.19.0', 'panel==0.*,>=0.12.1', 'rframe==0.*,>=0.1.6'],
    extras_require={"dev": ["bumpversion", "coverage", "flake8", "invoke", "isort", "nbsphinx", "pylint", "pytest", "sphinx", "sphinx-material", "tox", "yapf"]},
)

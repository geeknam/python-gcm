from distutils.core import setup

setup(
    name='python-gcm',
    version='0.1.4',
    packages=['gcm'],
    license=open('LICENSE').read(),
    author='Minh Nam Ngo',
    author_email='nam@namis.me',
    url='http://blog.namis.me/python-gcm/',
    description='Python client for Google Cloud Messaging for Android (GCM)',
    long_description=open('README.rst').read(),
    keywords='android gcm push notification google cloud messaging',
    tests_require = ['mock'],
)

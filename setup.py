from setuptools import setup

setup(
    name='python-gcm',
    version='0.4',
    packages=['gcm'],
    license='The MIT License (MIT)',
    author='Nam Ngo',
    author_email='nam@kogan.com.au',
    url='http://blog.namis.me/python-gcm/',
    description='Python client for Google Cloud Messaging for Android (GCM)',
    long_description=open('README.rst').read(),
    keywords='android gcm push notification google cloud messaging',
    install_requires=['requests'],
    tests_require=['mock', 'coverage'],
    test_suite='gcm.test',
    classifiers=(
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ),
)

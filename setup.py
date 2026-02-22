"""
PC-Omnifix Setup Configuration
=============================

Author: PC-Omnifix
Version: 1.0.0
"""

from setuptools import setup, find_packages
import os

# Read long description from README
here = os.path.abspath(os.path.dirname(__file__))
try:
    with open(os.path.join(here, 'README.md'), encoding='utf-8') as f:
        long_description = f.read()
except:
    long_description = 'PC-Omnifix - All-in-One PC Maintenance & Security Tool'

setup(
    name='pc-omnifix',
    version='1.0.0',
    description='All-in-One PC Maintenance & Security Tool',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='PC-Omnifix',
    author_email='contact@pc-omnifix.local',
    url='https://github.com/pc-omnifix/pc-omnifix',
    packages=find_packages(),
    python_requires='>=3.8',
    install_requires=[
        # No external dependencies - uses only standard library
    ],
    extras_require={
        'dev': [
            'pytest>=7.0.0',
            'pytest-cov>=3.0.0',
        ],
    },
    entry_points={
        'console_scripts': [
            'pc-omnifix=modules.firewall.cli:main',
            'pc-omnifix-firewall=modules.firewall.cli:main',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: End Users/Desktop',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: Microsoft :: Windows :: Windows 10',
        'Operating System :: Microsoft :: Windows :: Windows 11',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: Security',
        'Topic :: System :: Networking :: Firewalls',
    ],
    keywords='firewall windows security networking protection',
    project_urls={
        'Bug Reports': 'https://github.com/pc-omnifix/pc-omnifix/issues',
        'Source': 'https://github.com/pc-omnifix/pc-omnifix',
    },
)

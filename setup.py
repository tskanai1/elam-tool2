import setuptools

with open('requirements.txt') as requirements_file:
    install_requirements = requirements_file.read().splitlines()

setuptools.setup(
    name="elam-tool2",
    version="1.2.0",
    description="elam tool",
    author="Japan ACI Team",
    author_email="tskanai@cisco.com",
    packages=["elam_tool2"],
    install_requires=install_requirements,
    entry_points={
        'console_scripts':[
            "elam_report_generator=elam_tool2.elam_report_generator:main",
            "elam_multi_dev=elam_tool2.elam_multi_dev:main"
        ],
    }
)

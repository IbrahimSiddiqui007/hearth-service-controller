"""Curated official help links. Inventory metadata never supplies executable actions."""
MICROSOFT_REMOVE = 'https://support.microsoft.com/en-us/windows/uninstall-or-remove-apps-and-programs-in-windows-4b55f974-2cc6-2d2b-d092-5905080eaf98'
AUTODESK_REMOVE = 'https://www.autodesk.com/support/download-install/individuals/manage/uninstall-autodesk-software'


def guides(name, publisher='', kind='application', os_name='Windows', source=''):
    text = (str(name) + ' ' + str(publisher)).casefold()
    if os_name in ('Darwin', 'macOS'):
        office = any(label in text for label in ('microsoft 365', 'microsoft office', 'microsoft word', 'microsoft excel', 'microsoft powerpoint', 'microsoft outlook'))
        return {'documentation_url': 'https://help.autodesk.com/' if 'autodesk' in text or 'autocad' in text else 'https://support.microsoft.com/en-us/microsoft-365/' if office else 'https://support.apple.com/macos',
                'documentation_label': 'Autodesk documentation' if 'autodesk' in text or 'autocad' in text else 'Microsoft 365 help' if office else 'macOS help',
                'removal_url': 'https://support.microsoft.com/en-us/office/lifecycle/officeinstall/uninstall-office-for-mac' if office else AUTODESK_REMOVE if 'autodesk' in text or 'autocad' in text else 'https://support.apple.com/en-us/102610',
                'removal_label': 'Office for Mac uninstall guide' if office else 'Autodesk uninstall guide' if 'autodesk' in text or 'autocad' in text else 'Apple app removal guide',
                'removal_note': 'Use the vendor uninstaller when provided. Required macOS components cannot be removed; preserve your documents and review shared components.'}
    if os_name == 'Linux':
        sources = {'dpkg': ('https://manpages.debian.org/unstable/dpkg/dpkg-query.1.en.html', 'Debian package query reference', 'https://ubuntu.com/server/docs/how-to/software/package-management/', 'APT package management guide'),
                   'pacman': ('https://man.archlinux.org/man/pacman.8.en', 'Pacman reference', 'https://man.archlinux.org/man/pacman.8.en', 'Pacman removal guidance'),
                   'rpm': ('https://rpm.org/docs/6.0.x/man/rpm.8', 'RPM reference', '', '')}
        doc, label, removal, removal_label = sources.get(source, ('', '', '', ''))
        return {'documentation_url': doc, 'documentation_label': label, 'removal_url': removal, 'removal_label': removal_label,
                'removal_note': 'Review package dependencies and the installation method on this host before removal.' if removal else 'Identify the owning package or vendor installation method before removal; this entry does not establish a safe uninstall procedure.'}
    if 'autocad' in text:
        return {'documentation_url': 'https://help.autodesk.com/view/ACD/2026/ENU/',
                'documentation_label': 'AutoCAD 2026 help', 'removal_url': AUTODESK_REMOVE,
                'removal_label': 'Autodesk uninstall guide', 'removal_note': 'Follow the guide on the host where this application is installed.'}
    if 'autodesk' in text:
        return {'documentation_url': 'https://help.autodesk.com/', 'documentation_label': 'Autodesk documentation',
                'removal_url': AUTODESK_REMOVE, 'removal_label': 'Autodesk uninstall guide',
                'removal_note': 'Shared Autodesk components may be required by other installed products.'}
    if kind == 'service':
        return {'documentation_url': 'https://learn.microsoft.com/en-us/windows/win32/services/services',
                'documentation_label': 'Windows service documentation',
                'removal_url': 'https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-config',
                'removal_label': 'Service configuration guidance',
                'removal_note': 'A service is not an installed-app entry. Identify its owning product before changing or removing it; Windows components may be essential.'}
    if any(label in text for label in ('microsoft 365', 'office 365', 'microsoft office', 'microsoft.office')):
        return {'documentation_url': 'https://support.microsoft.com/en-us/microsoft-365/',
                'documentation_label': 'Microsoft 365 help',
                'removal_url': 'https://support.microsoft.com/en-us/office/lifecycle/officeinstall/uninstall-microsoft-365-or-office-from-a-pc',
                'removal_label': 'Microsoft 365 / Office uninstall guide',
                'removal_note': 'Choose the guide for your installation type on the listed host; suite applications may need to be removed together.'}
    if 'microsoft edge' in text or 'microsoft.microsoftedge' in text:
        return {'documentation_url': 'https://support.microsoft.com/en-us/edge/',
                'documentation_label': 'Microsoft Edge help', 'removal_url': MICROSOFT_REMOVE,
                'removal_label': 'Windows uninstall guide',
                'removal_note': 'Removal availability depends on the installed Windows edition and region. Follow the host\u2019s supported options.'}
    microsoft = 'microsoft' in text or name.casefold().startswith(('windows ', 'microsoft.'))
    return {'documentation_url': 'https://support.microsoft.com/' if microsoft else '',
            'documentation_label': 'Microsoft documentation' if microsoft else '',
            'removal_url': MICROSOFT_REMOVE, 'removal_label': 'Windows uninstall guide',
            'removal_note': 'Some built-in Windows components cannot be uninstalled. Use this guide on the listed host.'}

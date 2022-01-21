Name:           bluebinder
Version:        1.0
Release:        1%{?dist}
Summary:        a simple proxy for using android binder based bluetooth through vhci.

License:        GPLv2+
URL:            https://github.com/mer-hybris/bluebinder
Source:         %{name}-%{version}.tar.bz2

BuildRequires:  pkgconfig(libgbinder) >= 1.0.7
BuildRequires:  pkgconfig(bluez)
BuildRequires:  pkgconfig(libsystemd)
Requires:       gawk
Requires:       bluez5
Requires:       /usr/bin/getprop

%description
bluebinder is a simple proxy for using android binder based bluetooth through vhci.
The API which this depends on was introduced in Android 8 and should not disappear soon.
The kernel API this depends on can be enabled with CONFIG_BT_HCIVHCI.

%prep
%setup -q -n %{name}-%{version}

%build
%make_build

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT%{_unitdir}
cp bluebinder.service $RPM_BUILD_ROOT%{_unitdir}
mkdir $RPM_BUILD_ROOT%{_unitdir}/graphical.target.wants
ln -s ../bluebinder.service $RPM_BUILD_ROOT%{_unitdir}/graphical.target.wants/bluebinder.service
mkdir -p $RPM_BUILD_ROOT%{_bindir}/droid/
cp bluebinder_post.sh $RPM_BUILD_ROOT%{_bindir}/droid/
cp bluebinder_wait.sh $RPM_BUILD_ROOT%{_bindir}/droid/

%clean
rm -rf $RPM_BUILD_ROOT
make clean

%files
%defattr(-,root,root,-)
%{_sbindir}/bluebinder
%{_unitdir}/graphical.target.wants/bluebinder.service
%{_unitdir}/bluebinder.service
%{_bindir}/droid/bluebinder_post.sh
%{_bindir}/droid/bluebinder_wait.sh

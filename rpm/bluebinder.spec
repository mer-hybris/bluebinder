Name:           bluebinder
Version:        1.0.0
Release:        1%{?dist}
Summary:        a simple proxy for using android binder based bluetooth through vhci.

Group:          Applications/System
License:        GPLv2+
URL:            https://github.com/mer-hybris/bluebinder
Source:         %{name}-%{version}.tar.bz2

BuildRequires:  libgbinder-devel >= 1.0.7
BuildRequires:  pkgconfig(bluez5)
BuildRequires:  pkgconfig(libsystemd)
Requires:       bluez5
Requires:       /usr/bin/getprop

%description
bluebinder is a simple proxy for using android binder based bluetooth through vhci.
The API which this depends on was introduced in Android 8 and should not disappear soon.
The kernel API this depends on can be enabled with CONFIG_BT_HCIVHCI.

%prep
%setup -q -n %{name}-%{version}

%build
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/lib/systemd/system
cp bluebinder.service $RPM_BUILD_ROOT/lib/systemd/system
mkdir $RPM_BUILD_ROOT/lib/systemd/system/graphical.target.wants
ln -s ../bluebinder.service $RPM_BUILD_ROOT/lib/systemd/system/graphical.target.wants/bluebinder.service
mkdir -p $RPM_BUILD_ROOT/usr/bin/droid/
cp bluebinder_wait.sh $RPM_BUILD_ROOT/usr/bin/droid/

%clean
rm -rf $RPM_BUILD_ROOT
make clean

%files
%defattr(-,root,root,-)
/usr/sbin/bluebinder
/lib/systemd/system/graphical.target.wants/bluebinder.service
/lib/systemd/system/bluebinder.service
/usr/bin/droid/bluebinder_wait.sh

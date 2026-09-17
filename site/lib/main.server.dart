/// Static Jaspr documentation site for pqtransport.
library;

import 'package:jaspr/dom.dart';
import 'package:jaspr/server.dart';
import 'package:jaspr_content/components/callout.dart';
import 'package:jaspr_content/components/image.dart';
import 'package:jaspr_content/components/sidebar.dart';
import 'package:jaspr_content/jaspr_content.dart';
import 'package:jaspr_content/theme.dart';

import 'components/site_header.dart';
import 'main.server.options.dart';

void main() {
  Jaspr.initializeApp(options: defaultServerOptions);

  runApp(
    ContentApp(
      eagerlyLoadAllPages: true,
      templateEngine: MustacheTemplateEngine(),
      parsers: [MarkdownParser()],
      extensions: [HeadingAnchorsExtension(), TableOfContentsExtension()],
      components: [Callout(), Image(zoom: true)],
      layouts: [
        DocsLayout(
          header: const SiteHeader(),
          sidebar: const Sidebar(
            groups: [
              SidebarGroup(
                links: [SidebarLink(text: 'Overview', href: './')],
              ),
              SidebarGroup(
                title: 'Package',
                links: [
                  SidebarLink(text: 'Getting Started', href: 'getting-started'),
                  SidebarLink(text: 'Architecture', href: 'architecture'),
                  SidebarLink(text: 'Hybrid Groups', href: 'hybrid'),
                  SidebarLink(text: 'Protocols', href: 'protocols'),
                  SidebarLink(text: 'API Guide', href: 'api'),
                  SidebarLink(text: 'Cookbook', href: 'cookbook'),
                  SidebarLink(text: 'Platform Support', href: 'platform'),
                ],
              ),
              SidebarGroup(
                title: 'Evidence',
                links: [
                  SidebarLink(text: 'Features', href: 'features'),
                  SidebarLink(text: 'Claim Boundary', href: 'claim-boundary'),
                  SidebarLink(text: 'Bugs', href: 'bugs'),
                  SidebarLink(text: 'Roadmap', href: 'roadmap'),
                  SidebarLink(text: 'v0.1.0 Release', href: 'release'),
                ],
              ),
              SidebarGroup(
                title: 'Family',
                links: [SidebarLink(text: 'Sister packages', href: 'family')],
              ),
            ],
          ),
          footer: footer(classes: 'site-footer', [
            p([
              Component.text(
                'pqtransport v0.1.0. Built with Dart and Jaspr. '
                'Not a FIPS 140 module. ',
              ),
              a(
                href: 'https://github.com/turkananation/pqtransport',
                target: Target.blank,
                [Component.text('GitHub')],
              ),
              Component.text(' · '),
              a(
                href: 'https://turkananation.github.io/pqcrypto',
                target: Target.blank,
                [Component.text('pqcrypto')],
              ),
              Component.text(' · '),
              a(
                href: 'https://turkananation.github.io/pqforge',
                target: Target.blank,
                [Component.text('pqforge')],
              ),
              Component.text(' · '),
              a(
                href: 'https://turkananation.github.io/swissarmyknife',
                target: Target.blank,
                [Component.text('swissarmyknife')],
              ),
            ]),
          ]),
        ),
      ],
      theme: ContentTheme(
        primary: ThemeColor(Color('#0f766e'), dark: Color('#b6f25c')),
        background: ThemeColor(Color('#f3f6f1'), dark: Color('#070d14')),
        text: ThemeColor(Color('#13211a'), dark: Color('#e8f4ef')),
        colors: [
          ContentColors.links.apply(
            ThemeColor(Color('#0f766e'), dark: Color('#4ee0d4')),
          ),
          ContentColors.quoteBorders.apply(
            ThemeColor(Color('#b45309'), dark: Color('#f5c35b')),
          ),
          ContentColors.preBg.apply(
            ThemeColor(Color('#10221c'), dark: Color('#050b12')),
          ),
        ],
      ),
    ),
  );
}

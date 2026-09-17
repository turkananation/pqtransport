import 'package:jaspr/dom.dart';
import 'package:jaspr/jaspr.dart';
import 'package:jaspr_content/components/github_button.dart';
import 'package:jaspr_content/components/sidebar_toggle_button.dart';
import 'package:jaspr_content/components/theme_toggle.dart';

/// Branded header for the pqtransport documentation site.
class SiteHeader extends StatelessComponent {
  /// Creates the site header.
  const SiteHeader({super.key});

  @override
  Component build(BuildContext context) {
    return Component.fragment([
      Document.head(children: [Style(styles: _styles)]),
      header(classes: 'pqt-header', [
        const SidebarToggleButton(),
        a(classes: 'pqt-title', href: './', [
          img(src: 'images/logo.svg', alt: 'pqtransport logo'),
          span([Component.text('pqtransport')]),
        ]),
        nav(classes: 'pqt-nav', [
          a(href: 'hybrid', [Component.text('Hybrid')]),
          a(href: 'protocols', [Component.text('Protocols')]),
          a(href: 'api', [Component.text('API')]),
          a(href: 'claim-boundary', [Component.text('Boundary')]),
          a(href: 'family', [Component.text('Family')]),
          const ThemeToggle(),
          const GitHubButton(repo: 'turkananation/pqtransport'),
        ]),
      ]),
    ]);
  }

  static List<StyleRule> get _styles => [
    css('.pqt-header', [
      css('&').styles(
        height: 4.rem,
        display: Display.flex,
        alignItems: AlignItems.center,
        gap: Gap.column(.875.rem),
        padding: Padding.symmetric(horizontal: 1.rem, vertical: .25.rem),
        margin: Margin.symmetric(horizontal: Unit.auto),
        border: Border.only(
          bottom: BorderSide(color: Color('#b6f25c22'), width: 1.px),
        ),
        backgroundColor: Color(
          'color-mix(in srgb, var(--background) 88%, transparent)',
        ),
        raw: {'backdrop-filter': 'blur(14px)'},
      ),
      css.media(MediaQuery.all(minWidth: 768.px), [
        css('&').styles(padding: Padding.symmetric(horizontal: 2.5.rem)),
      ]),
      css('.pqt-title', [
        css('&').styles(
          display: Display.inlineFlex,
          flex: Flex(basis: 16.rem),
          alignItems: AlignItems.center,
          gap: Gap.column(.75.rem),
          minWidth: Unit.zero,
        ),
        css('img').styles(height: 1.75.rem, width: 1.75.rem),
        css('span').styles(
          fontWeight: FontWeight.w800,
          letterSpacing: Unit.zero,
          whiteSpace: WhiteSpace.noWrap,
        ),
      ]),
      css('.pqt-nav', [
        css('&').styles(
          display: Display.flex,
          flex: Flex(grow: 1),
          alignItems: AlignItems.center,
          justifyContent: JustifyContent.end,
          gap: Gap.column(.35.rem),
          overflow: Overflow.hidden,
        ),
        css('> a').styles(
          display: Display.none,
          padding: Padding.symmetric(horizontal: .7.rem, vertical: .45.rem),
          radius: BorderRadius.circular(.375.rem),
          fontSize: .875.rem,
          fontWeight: FontWeight.w600,
        ),
        css('> a:hover').styles(backgroundColor: Color('#b6f25c1a')),
        css.media(MediaQuery.all(minWidth: 760.px), [
          css('> a').styles(display: Display.inlineFlex),
        ]),
      ]),
    ]),
  ];
}

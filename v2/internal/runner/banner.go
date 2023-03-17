package runner

import (
	"fmt"

	"github.com/projectdiscovery/gologger"

)
var banner = fmt.Sprintf("\n %c[1;40;32m%s%c[0m\n\n", 0x1B, `
    ▄█     █▄   ▄██████▄   ▄██████▄   ▄█       ███    █▄   ▄██████▄
  ███     ███ ███    ███ ███    ███ ███       ███    ███ ███    ███
 ███     ███ ███    ███ ███    ███ ███       ███    ███ ███    ███
███ ▄█▄ ███ ███    ███ ███    ███ ███▌    ▄ ███    ███ ███    ███
 ▀███▀███▀   ▀██████▀   ▀██████▀  █████▄▄██ ████████▀   ▀██████▀
`, 0x1B)

// showBanner is used to show the banner to the user
func showBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("\t\tgithub.com/wooluo\n\n")

	gologger.Print().Label("WRN").Msgf("开发者不承担任何责任，也不对任何误用或损坏负责。\n")
	gologger.Print().Label("WRN").Msgf("该工具请勿用于非法用途，请遵守网络安全法，否则后果自负。\n")
}


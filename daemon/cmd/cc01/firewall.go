package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
)

func runFirewall(args []string) error {
	if len(args) == 0 {
		firewallUsage()
		return flag.ErrHelp
	}

	switch args[0] {
	case "add":
		return firewallAdd(args[1:])
	case "del":
		return firewallDel(args[1:])
	case "list":
		return firewallList(args[1:])
	case "test":
		return firewallTest(args[1:])
	case "mode":
		return firewallMode(args[1:])
	case "flush":
		return firewallFlush(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "cc01 firewall: noma'lum buyruq: %s\n\n", args[0])
		firewallUsage()
		return flag.ErrHelp
	}
}

func firewallUsage() {
	fmt.Fprint(os.Stderr, `cc01 firewall — eBPF policy

  add   --allow|--deny (--src CIDR | --dst CIDR) [--proto tcp] [--port N]
  del   <rule-id>
  list  [--json] [--in|--out]
  test  (--src ADDR | --dst ADDR) [--proto tcp] [--port N]
  mode  enforce|dry-run
  flush --force

Yo'nalish --src yoki --dst bilan tanlanadi:

  --src   kirish — "kim BIZGA murojaat qilyapti"
  --dst   chiqish — "biz KIMGA murojaat qilyapmiz"

Ikkalasini birga berib bo'lmaydi: qoidalar bir tomondagi prefiks
bo'yicha guruhlanadi (DEV_SPEC §4.2).

`)
}

// firewallTarget --src yoki --dst dan yo'nalish va prefiksni
// aniqlaydi.
//
// Ikkalasi ham berilsa xato: "manbadan maqsadga" shaklidagi qoidani
// hozirgi kalit sxemasi ifodalay olmaydi va buni jimgina bir
// tomonga aylantirish operatorni aldardi.
func firewallTarget(src, dst string) (cc01v1.FirewallDirection, string, error) {
	switch {
	case src != "" && dst != "":
		return 0, "", errors.New(
			"--src va --dst birga berilmaydi: qoidalar bir tomondagi prefiks " +
				"bo'yicha guruhlanadi")
	case src != "":
		return cc01v1.FirewallDirection_FIREWALL_DIRECTION_INGRESS, src, nil
	case dst != "":
		return cc01v1.FirewallDirection_FIREWALL_DIRECTION_EGRESS, dst, nil
	default:
		return 0, "", errors.New("--src yoki --dst ko'rsating")
	}
}

// parseProto protokol nomini raqamga aylantiradi.
func parseProto(name string) (uint32, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "any":
		return 0, nil
	case "tcp":
		return 6, nil
	case "udp":
		return 17, nil
	case "icmp", "icmpv6", "icmp6":
		return 58, nil
	}

	if number, err := strconv.ParseUint(name, 10, 8); err == nil {
		return uint32(number), nil
	}
	return 0, fmt.Errorf("noma'lum protokol: %s (tcp, udp, icmpv6 yoki raqam)", name)
}

func protoName(number uint32) string {
	switch number {
	case 0:
		return "any"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 58:
		return "icmpv6"
	default:
		return strconv.FormatUint(uint64(number), 10)
	}
}

func portName(port uint32) string {
	if port == 0 {
		return "any"
	}
	return strconv.FormatUint(uint64(port), 10)
}

func directionName(d cc01v1.FirewallDirection) string {
	if d == cc01v1.FirewallDirection_FIREWALL_DIRECTION_EGRESS {
		return "out"
	}
	return "in"
}

func verdictName(v cc01v1.FirewallVerdict) string {
	if v == cc01v1.FirewallVerdict_FIREWALL_VERDICT_ALLOW {
		return "allow"
	}
	return "deny"
}

func firewallAdd(args []string) error {
	set := flag.NewFlagSet("firewall add", flag.ContinueOnError)
	socket := socketFlag(set)
	allow := set.Bool("allow", false, "ruxsat berish")
	deny := set.Bool("deny", false, "taqiqlash")
	src := set.String("src", "", "manba prefiksi (kirish qoidasi)")
	dst := set.String("dst", "", "maqsad prefiksi (chiqish qoidasi)")
	proto := set.String("proto", "", "tcp, udp, icmpv6 yoki raqam")
	port := set.Uint("port", 0, "maqsad porti; 0 = istalgan")
	ruleID := set.Uint("id", 0, "qoida identifikatori; 0 = avtomatik")
	comment := set.String("comment", "", "izoh (audit uchun)")

	if err := set.Parse(args); err != nil {
		return err
	}

	if *allow == *deny {
		return errors.New("--allow yoki --deny dan bittasini tanlang")
	}

	direction, prefix, err := firewallTarget(*src, *dst)
	if err != nil {
		return err
	}

	protoNumber, err := parseProto(*proto)
	if err != nil {
		return err
	}

	verdict := cc01v1.FirewallVerdict_FIREWALL_VERDICT_DROP
	if *allow {
		verdict = cc01v1.FirewallVerdict_FIREWALL_VERDICT_ALLOW
	}

	client, closeConn, err := connectFirewall(*socket)
	if err != nil {
		return err
	}
	defer closeConn()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	response, err := client.AddRule(ctx, &cc01v1.AddRuleRequest{
		Direction: direction,
		Prefix:    prefix,
		Port:      uint32(*port),
		Proto:     protoNumber,
		Verdict:   verdict,
		RuleId:    uint32(*ruleID),
		Comment:   *comment,
	})
	if err != nil {
		return err
	}

	rule := response.GetRule()
	fmt.Printf("✔ qoida #%d qo'shildi: %s %s %s port=%s proto=%s\n",
		rule.GetRuleId(), verdictName(rule.GetVerdict()),
		directionName(rule.GetDirection()), rule.GetPrefix(),
		portName(rule.GetPort()), protoName(rule.GetProto()))

	// Dry-run rejimida qoida YOZILADI, lekin qo'llanmaydi. Buni
	// aytmasak operator qoida ishlayapti deb o'ylardi.
	return warnIfDryRun(ctx, client)
}

// warnIfDryRun rejim dry-run bo'lsa ogohlantiradi.
func warnIfDryRun(ctx context.Context, client cc01v1.FirewallServiceClient) error {
	list, err := client.ListRules(ctx, &cc01v1.ListRulesRequest{})
	if err != nil {
		return nil // ogohlantirish muhim emas, xatoni yashirmaymiz
	}
	if !list.GetEnforce() {
		fmt.Println("  ⚠ rejim: dry-run — qoidalar hisoblanadi, lekin QO'LLANMAYDI")
		fmt.Println("    yoqish: cc01 firewall mode enforce")
	}
	return nil
}

func firewallDel(args []string) error {
	set := flag.NewFlagSet("firewall del", flag.ContinueOnError)
	socket := socketFlag(set)
	if err := set.Parse(args); err != nil {
		return err
	}

	if set.NArg() != 1 {
		return errors.New("qoida identifikatorini ko'rsating: cc01 firewall del <id>")
	}

	ruleID, err := strconv.ParseUint(set.Arg(0), 10, 32)
	if err != nil {
		return fmt.Errorf("qoida identifikatori: %w", err)
	}

	client, closeConn, err := connectFirewall(*socket)
	if err != nil {
		return err
	}
	defer closeConn()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	response, err := client.DelRule(ctx, &cc01v1.DelRuleRequest{RuleId: uint32(ruleID)})
	if err != nil {
		return err
	}

	fmt.Printf("✔ qoida #%d o'chirildi\n", response.GetRule().GetRuleId())
	return nil
}

func firewallList(args []string) error {
	set := flag.NewFlagSet("firewall list", flag.ContinueOnError)
	socket := socketFlag(set)
	asJSON := set.Bool("json", false, "JSON chiqarish")
	onlyIn := set.Bool("in", false, "faqat kirish qoidalari")
	onlyOut := set.Bool("out", false, "faqat chiqish qoidalari")

	if err := set.Parse(args); err != nil {
		return err
	}
	if *onlyIn && *onlyOut {
		return errors.New("--in va --out birga berilmaydi")
	}

	direction := cc01v1.FirewallDirection_FIREWALL_DIRECTION_UNSPECIFIED
	switch {
	case *onlyIn:
		direction = cc01v1.FirewallDirection_FIREWALL_DIRECTION_INGRESS
	case *onlyOut:
		direction = cc01v1.FirewallDirection_FIREWALL_DIRECTION_EGRESS
	}

	client, closeConn, err := connectFirewall(*socket)
	if err != nil {
		return err
	}
	defer closeConn()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	response, err := client.ListRules(ctx, &cc01v1.ListRulesRequest{
		OnlyDirection: direction,
	})
	if err != nil {
		return err
	}

	if *asJSON {
		return emitJSON(response)
	}

	mode := "enforce"
	if !response.GetEnforce() {
		mode = "dry-run"
	}
	fmt.Printf("rejim: %s   avlod: %d\n\n", mode, response.GetGeneration())

	if len(response.GetRules()) == 0 {
		fmt.Println("Qoida yo'q — deny-by-default amal qiladi.")
		if response.GetEnforce() {
			fmt.Println("⚠ enforce rejimida bu BUTUN overlay trafigini kesadi.")
		}
		return nil
	}

	writer := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(writer, "ID\tYO'L\tHUKM\tPREFIKS\tPORT\tPROTO\tURISH")

	for _, rule := range response.GetRules() {
		prefix := rule.GetPrefix()
		if prefix == "" {
			prefix = fmt.Sprintf("(guruh %d)", rule.GetIdentity())
		}
		fmt.Fprintf(writer, "%d\t%s\t%s\t%s\t%s\t%s\t%d\n",
			rule.GetRuleId(), directionName(rule.GetDirection()),
			verdictName(rule.GetVerdict()), prefix,
			portName(rule.GetPort()), protoName(rule.GetProto()), rule.GetHits())
	}

	return writer.Flush()
}

func firewallTest(args []string) error {
	set := flag.NewFlagSet("firewall test", flag.ContinueOnError)
	socket := socketFlag(set)
	src := set.String("src", "", "manba manzili (kirish yo'li)")
	dst := set.String("dst", "", "maqsad manzili (chiqish yo'li)")
	proto := set.String("proto", "", "tcp, udp, icmpv6 yoki raqam")
	port := set.Uint("port", 0, "maqsad porti")

	if err := set.Parse(args); err != nil {
		return err
	}

	direction, addr, err := firewallTarget(*src, *dst)
	if err != nil {
		return err
	}

	protoNumber, err := parseProto(*proto)
	if err != nil {
		return err
	}

	client, closeConn, err := connectFirewall(*socket)
	if err != nil {
		return err
	}
	defer closeConn()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	response, err := client.TestRule(ctx, &cc01v1.TestRuleRequest{
		Direction: direction,
		Addr:      addr,
		Port:      uint32(*port),
		Proto:     protoNumber,
	})
	if err != nil {
		return err
	}

	fmt.Printf("  yo'nalish     %s\n", directionName(direction))
	fmt.Printf("  manzil        %s port=%s proto=%s\n",
		addr, portName(uint32(*port)), protoName(protoNumber))

	if prefix := response.GetPrefix(); prefix != "" {
		fmt.Printf("  guruh         %d (%s)\n", response.GetIdentity(), prefix)
	} else {
		fmt.Printf("  guruh         %d (prefiks bog'lanmagan)\n", response.GetIdentity())
	}

	if response.GetMatched() {
		rule := response.GetRule()
		fmt.Printf("  qoida         #%d — %s\n", rule.GetRuleId(), verdictName(rule.GetVerdict()))
	} else {
		fmt.Println("  qoida         topilmadi → deny-by-default")
	}

	fmt.Printf("  hukm          %s\n", verdictName(response.GetVerdict()))

	// Dry-run'da hukm QO'LLANMAYDI — buni aytmasak natija
	// chalg'ituvchi bo'lardi.
	if !response.GetEnforce() {
		fmt.Println("  ⚠ rejim dry-run — hukm hisoblanadi, lekin qo'llanmaydi")
	}

	return nil
}

func firewallMode(args []string) error {
	set := flag.NewFlagSet("firewall mode", flag.ContinueOnError)
	socket := socketFlag(set)
	if err := set.Parse(args); err != nil {
		return err
	}

	if set.NArg() != 1 {
		return errors.New("rejimni ko'rsating: enforce yoki dry-run")
	}

	var enforce bool
	switch strings.ToLower(set.Arg(0)) {
	case "enforce":
		enforce = true
	case "dry-run", "dryrun":
		enforce = false
	case "panic":
		// Hujjat §4.4 da panic rejimi bor, lekin u qurilmagan.
		// Uni jimgina enforce'ga aylantirish operatorni aldardi.
		return errors.New("panic rejimi hali qurilmagan (DEV_SPEC §4.4)")
	default:
		return fmt.Errorf("noma'lum rejim: %s (enforce yoki dry-run)", set.Arg(0))
	}

	client, closeConn, err := connectFirewall(*socket)
	if err != nil {
		return err
	}
	defer closeConn()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	response, err := client.SetMode(ctx, &cc01v1.SetModeRequest{Enforce: enforce})
	if err != nil {
		return err
	}

	if response.GetEnforce() {
		fmt.Println("✔ rejim: enforce — hukmlar qo'llanadi")
	} else {
		fmt.Println("✔ rejim: dry-run — hukmlar hisoblanadi, lekin qo'llanmaydi")
	}
	return nil
}

func firewallFlush(args []string) error {
	set := flag.NewFlagSet("firewall flush", flag.ContinueOnError)
	socket := socketFlag(set)
	force := set.Bool("force", false, "tasdiqlash")

	if err := set.Parse(args); err != nil {
		return err
	}

	// Deny-by-default siyosatida tozalash BUTUN trafikni kesadi.
	// Tasdiqlashsiz bajarilmaydi.
	if !*force {
		return errors.New(
			"tozalash butun overlay trafigini kesadi (deny-by-default); " +
				"tasdiqlash uchun --force qo'shing")
	}

	client, closeConn, err := connectFirewall(*socket)
	if err != nil {
		return err
	}
	defer closeConn()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	response, err := client.Flush(ctx, &cc01v1.FlushRequest{})
	if err != nil {
		return err
	}

	fmt.Printf("✔ %d ta qoida o'chirildi\n", response.GetRemoved())
	return nil
}

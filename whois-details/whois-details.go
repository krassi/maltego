package main

import (
	"github.com/sensepost/maltegolocal/maltegolocal"
	"github.com/likexian/whois-parser-go"
	"strings"
	"os/exec"
	"regexp"
	"log"
	"fmt"
	"os"
)

func main() {
	lt := maltegolocal.ParseLocalArguments(os.Args)
	Domain := lt.Value
	TRX := maltegolocal.MaltegoTransform{}

	if Domain == "" {
		TRX.AddUIMessage("Domain name missing.", "Error!")
		return
	}

	out, err := exec.Command("/usr/bin/whois", Domain).Output()
	if err != nil {
		log.Fatal(err)
	}

	whois_info, err := whois_parser.Parse(string(out))
	if err != nil {
		TRX.AddUIMessage("ERROR: Unable to parse WHOIS output for " +
			Domain + "!","Error")
		return
	}

	TRX = *processDomain( whois_info.Registrar, &TRX)

	TRX = *processSection( whois_info.Registrant, "Registrant", &TRX)
	TRX = *processSection( whois_info.Admin, "Admin", &TRX)
	TRX = *processSection( whois_info.Tech, "Tech", &TRX)

	TRX = *processRegistrar( whois_info.Registrar, &TRX)

	TRX.AddUIMessage("completed!","Inform")
	fmt.Println(TRX.ReturnOutput())
}



func processDomain( contact whois_parser.Registrar, TRX *maltegolocal.MaltegoTransform) *maltegolocal.MaltegoTransform  {
	BaseEnt := TRX.AddEntity("maltego.Domain", contact.DomainName)

	// Process domain specific properties in the Registrar section
	for _, i := range strings.Split(contact.NameServers, ",") {
		TRX.AddEntity("maltego.NSRecord", i)
	}
	BaseEnt.AddProperty("domain.id", "domain.id",
		"nostrict", contact.DomainId)
	BaseEnt.AddProperty("domain.created_date", "domain.created_date",
		"nostrict", contact.CreatedDate)
	BaseEnt.AddProperty("domain.updated_date", "domain.updated_date",
		"nostrict", contact.UpdatedDate)
	BaseEnt.AddProperty("domain.expiration_date", "domain.expiration_date",
		"nostrict", contact.ExpirationDate)
	BaseEnt.AddProperty("domain.DNSSEC", "domain.DNSSEC",
		"nostrict", contact.DomainDNSSEC)

	// clean up domain status field (remove IANA URLs)
	clnStat := regexp.MustCompile(` http(s|)://.*?(,|$| )`)
	domStat := clnStat.ReplaceAllString(contact.DomainStatus, `$2`)
	BaseEnt.AddProperty("domain.status", "domain.status", "nostrict", domStat)

	return TRX
}
func parseAndVerifyPhone( cPhone string) (phone, cc, rest string) {
	var matchWhoisNumber = regexp.MustCompile(`^\+[0-9]+\.[0-9]+$`)

	if matchWhoisNumber.MatchString(cPhone) {
		// Valid number: WHOIS phone format is +CC.NNNNNNNN
		pp := strings.Split(cPhone, ".")
		phone = pp[0] + pp[1]
		cc = pp[0]
		rest = pp[1]
	} else {
		// If phone is in weird format (maybe fraudulent) use as is
		phone = cPhone
	}
	return
}

func assignNumbers( NewEnt *maltegolocal.MaltegoEntityObj, phone, cc, rest, ext string) {
	if cc != "" {
		rl := len(rest)
		NewEnt.AddProperty("phonenumber.countrycode",
			"phonenumber.countrycode" , "nostrict", cc)
		NewEnt.AddProperty("phonenumber.citycode",
			"phonenumber.citycode" , "nostrict", rest[0:rl-7])
		NewEnt.AddProperty("phonenumber.areacode", "phonenumber.areacode" ,
			"nostrict", rest[rl-7:rl-4])
		NewEnt.AddProperty("phonenumber.lastnumbers", "phonenumber.lastnumbers",
			"nostrict", rest[rl-4:])
	}
	if ext != "" {
		NewEnt.AddProperty("extension", "extension" , "nostrict", ext)
	}
}

func processSection(	contact whois_parser.Registrant, 
			sectionName string, 
			TRX *maltegolocal.MaltegoTransform) *maltegolocal.MaltegoTransform  {


	entEmail := TRX.AddEntity("maltego.EmailAddress", contact.Email)
	entEmail.AddDisplayInformation("<p>Contact Type: " +
		sectionName + " Email</p>", "Other")
	entEmail.SetWeight(200)

	phone, cc, rest := parseAndVerifyPhone(contact.Phone)
	entPhone := TRX.AddEntity("maltego.PhoneNumber", phone)
	assignNumbers( entPhone, phone, cc, rest, contact.PhoneExt);
	entPhone.AddDisplayInformation("<p>Contact Type: " +
		sectionName + " Phone</p>", "Other")
	entPhone.SetWeight(200)

	phone, cc, rest = parseAndVerifyPhone(contact.Fax)
	entFax := TRX.AddEntity("maltego.PhoneNumber", phone)
	assignNumbers( entFax, phone, cc, rest, contact.FaxExt);
	entFax.AddDisplayInformation("<p>Contact Type: " +
		sectionName + " Fax</p>", "Other")
	entFax.SetWeight(200)

	entName := TRX.AddEntity("maltego.Person", contact.Name)
	entName.AddDisplayInformation("<p>Contact Type: " +
		sectionName + " Name</p>", "Other")
	entName.SetWeight(200)

	// Handles Registrant, Admin and Tech ID - storing it in the Person entity for now
	//entID := TRX.AddEntity("maltego.", contact.ID)
	entName.AddDisplayInformation("<p>" + sectionName +
		" ID: " + contact.ID + "</p>", "Other")

	entOrg := TRX.AddEntity("maltego.Company", contact.Organization)
	entOrg.AddDisplayInformation("<p>Contact Type: " +
		sectionName + " Organization</p>", "Other")
	entOrg.SetWeight(200)

	//Location related stuff
	entLoc := TRX.AddEntity("maltego.Location", contact.Organization)
	entLoc.SetWeight(200)

	entLoc.AddProperty("country", "country" , "nostrict", contact.Country)
	entLoc.AddProperty("countrycode", "countrycode" , "nostrict", contact.Country) //**

	entLoc.AddProperty("city", "city" , "nostrict", contact.City)

	entLoc.AddProperty("location.area", "" , "nostrict", contact.Province)
	entLoc.AddProperty("location.areacode", "" , "nostrict", contact.Province) //**

	entLoc.AddProperty("streetaddress", "streetaddress" , "nostrict",
		contact.Street + " " + contact.StreetExt)
	entLoc.AddProperty("postal code", "postal code" , "nostrict", contact.PostalCode)

	// TODO
	//entLoc.AddProperty("longitude", "longitude" , "nostrict", contact.)
	//entLoc.AddProperty("latitude", "latitude" , "nostrict", contact.)
	// https://developers.google.com/maps/documentation/geocoding/intro
	// https://developers.google.com/maps/documentation/javascript/geocoding
	// https://developers.google.com/maps/documentation/geocoding/client-library

	//timezone
	// https://developers.google.com/maps/documentation/timezone/start
	// https://timezonedb.com/api

	//continent

	return TRX
}

func processRegistrar( contact whois_parser.Registrar, TRX *maltegolocal.MaltegoTransform) *maltegolocal.MaltegoTransform  {
	entReg := TRX.AddEntity("maltego.Company", contact.RegistrarName)
	entReg.AddProperty("registrar.iana_id", "registrar.iana_id",
		"nostrict", contact.RegistrarID) //**
	entReg.AddProperty("registrar.whois_server", "registrar.whois_server",
		"nostrict", contact.WhoisServer) //**
	entReg.AddProperty("registrar.referral_url", "registrar.referral_url",
		"nostrict", contact.ReferralURL) //**
	entReg.SetWeight(200)

// IANA Registrar List: https://www.iana.org/assignments/registrar-ids/registrar-ids.xhtml
//   Missing in the WHOIS parser library
//   Registrar Abuse Contact Email:
//   Registrar Abuse Contact Phone:
//	entReg.AddProperty("registrar.", "registrar." , "nostrict", contact.) //**

	return TRX
}


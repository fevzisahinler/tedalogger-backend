package validation

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
)

type Envelope struct {
	XMLName   xml.Name `xml:"soap:Envelope"`
	XmlnsXsi  string   `xml:"xmlns:xsi,attr"`
	XmlnsXsd  string   `xml:"xmlns:xsd,attr"`
	XmlnsSoap string   `xml:"xmlns:soap,attr"`
	Body      Body
}

type Body struct {
	XMLName           xml.Name `xml:"soap:Body"`
	TCKimlikNoDogrula TCKimlikNoDogrula
}

type TCKimlikNoDogrula struct {
	XMLName    xml.Name `xml:"TCKimlikNoDogrula"`
	Xmlns      string   `xml:"xmlns,attr"`
	TCKimlikNo string   `xml:"TCKimlikNo"`
	Ad         string   `xml:"Ad"`
	Soyad      string   `xml:"Soyad"`
	DogumYili  int      `xml:"DogumYili"`
}

type ResponseEnvelope struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    ResponseBody
}

type ResponseBody struct {
	XMLName                   xml.Name `xml:"Body"`
	TCKimlikNoDogrulaResponse TCKimlikNoDogrulaResponse
}

type TCKimlikNoDogrulaResponse struct {
	XMLName                 xml.Name `xml:"TCKimlikNoDogrulaResponse"`
	TCKimlikNoDogrulaResult bool     `xml:"TCKimlikNoDogrulaResult"`
}

func ValidateIdentity(tcKimlikNo, ad, soyad string, dogumYili int) (bool, error) {
	valid, err := ValidateTCKN(tcKimlikNo)
	if err != nil {
		return false, err
	}
	if !valid {
		return false, errors.New("Invalid TCKN")
	}

	logFile, err := os.OpenFile("kimlik_dogrulama.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return false, errors.New("log dosyası oluşturulamadı: " + err.Error())
	}
	defer logFile.Close()
	log.SetOutput(logFile)

	envelope := Envelope{
		XmlnsXsi:  "http://www.w3.org/2001/XMLSchema-instance",
		XmlnsXsd:  "http://www.w3.org/2001/XMLSchema",
		XmlnsSoap: "http://schemas.xmlsoap.org/soap/envelope/",
		Body: Body{
			TCKimlikNoDogrula: TCKimlikNoDogrula{
				Xmlns:      "http://tckimlik.nvi.gov.tr/WS",
				TCKimlikNo: tcKimlikNo,
				Ad:         ad,
				Soyad:      soyad,
				DogumYili:  dogumYili,
			},
		},
	}

	xmlData, err := xml.MarshalIndent(envelope, "", "  ")
	if err != nil {
		log.Printf("XML oluşturulamadı: %v", err)
		return false, err
	}

	req, err := http.NewRequest("POST", "https://tckimlik.nvi.gov.tr/Service/KPSPublic.asmx", bytes.NewBuffer(xmlData))
	if err != nil {
		log.Printf("HTTP isteği oluşturulamadı: %v", err)
		return false, err
	}
	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	req.Header.Set("SOAPAction", "http://tckimlik.nvi.gov.tr/WS/TCKimlikNoDogrula")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("HTTP isteği gönderilemedi: %v", err)
		return false, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Yanıt okunamadı: %v", err)
		return false, err
	}

	var responseEnvelope ResponseEnvelope
	err = xml.Unmarshal(body, &responseEnvelope)
	if err != nil {
		log.Printf("Yanıt ayrıştırılamadı: %v", err)
		return false, err
	}

	if responseEnvelope.Body.TCKimlikNoDogrulaResponse.TCKimlikNoDogrulaResult {
		log.Println("Kimlik doğrulama başarılı.")
		return true, nil
	}

	log.Println("Kimlik doğrulama başarısız.")
	return false, nil
}

func ValidateTCKN(tckn string) (bool, error) {
	if len(tckn) != 11 {
		return false, errors.New("TCKN must be 11 digits")
	}

	for _, c := range tckn {
		if c < '0' || c > '9' {
			return false, errors.New("TCKN must contain only digits")
		}
	}

	var digits [11]int
	for i, c := range tckn {
		digit, _ := strconv.Atoi(string(c))
		digits[i] = digit
	}

	sumOdd := digits[0] + digits[2] + digits[4] + digits[6] + digits[8]
	sumEven := digits[1] + digits[3] + digits[5] + digits[7]
	check1 := ((sumOdd * 7) - sumEven) % 10
	check2 := (sumOdd + sumEven + digits[9]) % 10

	if check1 != digits[9] || check2 != digits[10] {
		return false, errors.New("Invalid TCKN checksum")
	}

	return true, nil
}

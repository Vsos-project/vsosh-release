#!/usr/bin/env python3

import sys
import json
import argparse
import requests
import importlib.util
import os
import time
import re
from pathlib import Path
from datetime import datetime
from urllib.parse import urljoin

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class NVD:
    def __init__(self, api_key=None):
        self.cve_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.cpe_url = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0", "Accept": "application/json"})
        if api_key:
            self.session.headers.update({"apiKey": api_key})
            self.have_key = True
        else:
            self.have_key = False

    def get_cves_for_library(self, library_name, version=None):
        try:
            cpes = self._find_cpes(library_name)
            if not cpes:
                return []
            all_cves = []
            used_cpes = set()
            for cpe in cpes:
                if version:
                    parts = cpe.split(":")
                    parts[5] = version
                    cpe = ":".join(parts)
                if cpe not in used_cpes:
                    cves = self._get_cves_by_cpe(cpe)
                    all_cves.extend(cves)
                    used_cpes.add(cpe)
                    time.sleep(1 if self.have_key else 10)
            return all_cves
        except Exception as e:
            print(f"[NVD] Ошибка: {e}")
            return []

    def _find_cpes(self, library_name):
        try:
            params = {"keywordSearch": library_name, "resultsPerPage": 20}
            resp = self.session.get(self.cpe_url, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            cpes = []
            for product in data.get("products", []):
                cpe = product.get("cpe", {}).get("cpeName")
                if cpe and library_name.lower() in cpe.lower():
                    cpes.append(cpe)
            return cpes
        except Exception as e:
            print(f"[NVD] Ошибка поиска CPE: {e}")
            return []

    def _get_cves_by_cpe(self, cpe):
        params = {"cpeName": cpe, "resultsPerPage": 2000, "startIndex": 0}
        all_cves = []
        while True:
            try:
                resp = self.session.get(self.cve_url, params=params, timeout=30)
                resp.raise_for_status()
                data = resp.json()
                vulns = data.get("vulnerabilities", [])
                total = data.get("totalResults", 0)
                all_cves.extend(vulns)
                if len(all_cves) >= total or not vulns:
                    break
                params["startIndex"] = len(all_cves)
            except Exception as e:
                print(f"[NVD] Ошибка получения CVE: {e}")
                break
        return self._normalize(all_cves)

    def _normalize(self, raw_cves):
        normalized = []
        for item in raw_cves:
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("id", "UNKNOWN")
            desc = ""
            for d in cve_data.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            if not desc and cve_data.get("descriptions"):
                desc = cve_data["descriptions"][0].get("value", "")

            score = "N/A"
            metrics = cve_data.get("metrics", {})
            for ver in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if ver in metrics and metrics[ver]:
                    score = metrics[ver][0].get("cvssData", {}).get("baseScore", "N/A")
                    break

            published = cve_data.get("published", "")
            refs = [r.get("url", "") for r in cve_data.get("references", [])]

            normalized.append({
                "id": cve_id,
                "description": desc,
                "cvss_score": score,
                "published": published,
                "references": refs,
                "source": "NVD"
            })
        return normalized


class FSTEC:
    def __init__(self):
        self.base_url = "http://bdu.fstec.ru"
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0"})
        self.session.verify = False

    def get_cves_for_library(self, library_name, version=None):
        query = f'"{library_name}"'
        params = {"q": query}
        search_url = urljoin(self.base_url, "/search")
        try:
            resp = self.session.get(search_url, params=params, timeout=30)
            resp.raise_for_status()
        except Exception as e:
            print(f"[ФСТЭК] Ошибка запроса: {e}")
            return []

        time.sleep(1)
        cves = self._parse(resp.text)

        page_num = 1
        while True:
            m = re.search(r'<a\s+[^>]*href="([^"]*page=(\d+)[^"]*)"[^>]*>.*?(?:>).*?</a>', resp.text, re.I|re.S)
            if not m:
                break
            next_url = urljoin(self.base_url, m.group(1))
            if next_url == search_url or (m.group(2) and int(m.group(2)) <= page_num):
                break
            try:
                resp = self.session.get(next_url, timeout=30)
                resp.raise_for_status()
            except Exception as e:
                print(f"[ФСТЭК] Ошибка перехода на след. страницу: {e}")
                break
            time.sleep(1)
            cves.extend(self._parse(resp.text))
            page_num += 1

        return cves

    def _parse(self, html):
        blocks = re.findall(r'<h4[^>]*><a[^>]*>(.*?)</a></h4>(.*?)(?=<h4|\Z)', html, re.S|re.I)
        cves = []
        for title_html, content_html in blocks:
            vuln = self._parse_vuln(title_html + content_html)
            if vuln:
                vuln["source"] = "FSTEC"
                cves.append(vuln)
        return cves

    def _parse_vuln(self, text):
        res = {
            "id": "",
            "description": "",
            "cvss_score": "N/A",
            "published": "",
            "references": []
        }
        id_match = re.search(r'(BDU:\d+-\d+|CVE-\d{4}-\d+)', text, re.I)
        if id_match:
            res["id"] = id_match.group(1)

        title_match = re.search(r'<h4[^>]*>(.*?)</h4>', text, re.S|re.I)
        if title_match:
            desc = title_match.group(1)
        else:
            desc_match = re.search(rf'{re.escape(res["id"])}\s*(.*?)(?:<|$)', text, re.S|re.I)
            desc = desc_match.group(1) if desc_match else ""
        desc = re.sub(r'<[^>]+>', '', desc)
        desc = re.sub(r'^(BDU:\d+-\d+|CVE-\d{4}-\d+)\s*', '', desc, flags=re.I)
        res["description"] = desc.strip()

        date_pub = re.search(r'<strong>Дата публикации:</strong>\s*(.*?)(?:<br>|<p|<div|$)', text, re.S|re.I)
        if date_pub:
            res["published"] = date_pub.group(1).strip().replace('</small></p>', '')

        cve_refs = re.findall(r'CVE-\d{4}-\d+', text, re.I)
        if cve_refs:
            res["references"].extend(cve_refs)

        return res if res["id"] else None


class CVEScanner:
    def __init__(self, api_key=None, cache_file=None):
        self.nvd = NVD(api_key)
        self.fstec = FSTEC()
        self.cache_file = cache_file
        self.cache = {}
        if cache_file and os.path.exists(cache_file):
            try:
                with open(cache_file, 'r') as f:
                    self.cache = json.load(f)
            except:
                print(f"Не удалось загрузить кэш из {cache_file}")

    def _save_cache(self):
        if self.cache_file:
            try:
                with open(self.cache_file, 'w') as f:
                    json.dump(self.cache, f, indent=2, ensure_ascii=False)
            except Exception as e:
                print(f"Ошибка сохранения кэша: {e}")

    def get_cves_for_library(self, library_name, version=None):
        key = library_name
        if version:
            key += f"-{version}"
        if key in self.cache:
            return self.cache[key]

        all_cves = []
        sources = [self.nvd,self.fstec]
        for src in sources:
            try:
                cves = src.get_cves_for_library(library_name, version)
                all_cves.extend(cves)
            except Exception as e:
                print(f"Ошибка в {src.__class__.__name__}: {e}")

        unique = {}
        for c in all_cves:
            unique[c["id"]] = c
        result = list(unique.values())

        self.cache[key] = result
        self._save_cache()
        return result

    def scan_libraries(self, libraries):
        results = {}
        for lib, ver in libraries.items():
            print(f"  {lib} {ver if ver else ''}")
            cves = self.get_cves_for_library(lib, ver)
            results[lib] = {"version": ver, "cve_count": len(cves), "cves": cves}
        self._save_cache()
        return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Сканер CVE (NVD + ФСТЭК)")
    parser.add_argument("parser", help="файл с функцией parse()")
    parser.add_argument("file", help="файл зависимостей")
    parser.add_argument("-o", "--output", help="куда сохранить результат")
    parser.add_argument("-k", "--api-key", help="ключ NVD API")
    parser.add_argument("-c", "--cache-file", help="файл кэша")
    parser.add_argument("-v", "--verbose", action="store_true", help="подробнее")
    args = parser.parse_args()

    parser_file = Path(args.parser)
    if not parser_file.exists():
        print(f"Файл парсера {args.parser} не найден")
        sys.exit(1)

    spec = importlib.util.spec_from_file_location("custom_parser", parser_file)
    module = importlib.util.module_from_spec(spec)
    sys.modules["custom_parser"] = module
    try:
        spec.loader.exec_module(module)
    except Exception as e:
        print(f"Ошибка загрузки парсера: {e}")
        sys.exit(1)

    if not hasattr(module, "parse"):
        print(f"В файле {args.parser} нет функции parse()")
        sys.exit(1)

    parse_func = module.parse
    if not Path(args.file).exists():
        print(f"Файл {args.file} не найден")
        sys.exit(1)

    libraries = parse_func(args.file)


    print(f"Найдено {len(libraries)} зависимостей.\n")

    
    if not libraries:
        print("Зависимости не найдены")
        exit(0)

    scanner = CVEScanner(
        api_key=args.api_key,
        cache_file=args.cache_file,
    )

    print("Поиск CVE")
    results = scanner.scan_libraries(libraries)

    if args.output:
        out_file = args.output
    else:
        ts = datetime.now().strftime("%Y-%m-%d_%H:%M:%S")
        out_file = f"cve_results_{Path(args.file).stem}_{ts}.json"

    total_cves = sum(d["cve_count"] for d in results.values())
    libs_with_cves = sum(1 for d in results.values() if d["cve_count"] > 0)

    output_data = {
        "metadata": {
            "scan_date": datetime.now().isoformat(),
            "target_file": args.file,
            "parser": parser_file.stem,
            "sources": ["NVD", "FSTEC"]
        },
        "statistics": {
            "total_libraries": len(libraries),
            "libraries_with_cves": libs_with_cves,
            "total_cves_found": total_cves
        },
        "libraries": libraries,
        "scan_results": results
    }

    with open(out_file, "w") as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)

    print(f"Результаты сохранены в {out_file}\n")

    print("Итоги сканирования\n")
    print(f"Всего библиотек: {len(libraries)}")
    print(f"Из них с CVE: {libs_with_cves}")
    print(f"Всего найдено CVE: {total_cves}")

    if total_cves > 0:
        for lib, data in results.items():
            if data["cve_count"] == 0:
                continue
            print(f"\n{lib} {data['version'] or ''} ({data['cve_count']} CVE):")
            for cve in data["cves"][:3]:
                score = cve["cvss_score"]
                sev = ""
                if score != "N/A":
                    try:
                        s = float(score)
                        if s >= 9.0:
                            sev = "[КРИТ.] "
                        elif s >= 7.0:
                            sev = "[ВЫС.] "
                        elif s >= 4.0:
                            sev = "[СР.] "
                        else:
                            sev = "[НИЗ.] "
                    except:
                        pass
                print(f"  {sev}{cve['id']} ({cve['source']}): {cve['description'][:50]}...")
    else:
        print("Уязвимостей не найдено")

    critical = 0
    for d in results.values():
        for cve in d["cves"]:
            if cve["cvss_score"] != "N/A":
                try:
                    if float(cve["cvss_score"]) >= 9.0:
                        critical += 1
                except:
                    pass
    if critical > 0:
        print(f"ВНИМАНИЕ: {critical} критических уязвимостей (CVSS >= 9.0)")

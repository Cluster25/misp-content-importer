# Cluster25 MISP Importer Tool

## Legal notice

By accessing or using this script, sample code, application programming interface, tools, and/or associated
documentation (if any) (collectively, “Tools”), You (i) represent and warrant that You are entering into this Agreement
on behalf of a company, organization or another legal entity (“Entity”) that is currently a customer or partner of
DuskRise, Inc.(“DuskRise”), and (ii) have the authority to bind such Entity and such Entity agrees to be bound by
this Agreement. DuskRise grants Entity a non-exclusive, non-transferable, non-sublicensable, royalty free and limited
license to access and use the Tools solely for Entity’s internal business purposes and in accordance with its
obligations under any agreement(s) it may have with DuskRise. Entity acknowledges and agrees that DuskRise and its
licensors retain all right, title and interest in and to the Tools, and all intellectual property rights embodied
therein, and that Entity has no right, title or interest therein except for the express licenses granted hereunder and
that Entity will treat such Tools as DuskRise’s confidential information.

THE TOOLS ARE PROVIDED “AS-IS” WITHOUT WARRANTY OF ANY KIND, WHETHER EXPRESS, IMPLIED OR STATUTORY OR OTHERWISE.
DUSKRISE SPECIFICALLY DISCLAIMS ALL SUPPORT OBLIGATIONS AND ALL WARRANTIES, INCLUDING WITHOUT LIMITATION, ALL IMPLIED
WARRANTIES OF MERCHANTABILITY, FITNESS FOR PARTICULAR PURPOSE, TITLE, AND NON-INFRINGEMENT. IN NO EVENT SHALL
DUSKRISE BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
BUT NOT LIMITED TO, LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
THE USE OF THE TOOLS, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

© Copyright DuskRise 2023



## Description

Cluster25 MISP Importer Tool is a tool used to import data from the Cluster25 Intel API in your MISP instance. It pulls reports, indicators and actors from Intel API and pushes them into MISP via MISP API. It creates a new event for every report and actor document imported and adds them some attributes or object for some of their components. In the case of indicators, they are added as attributes of a single timestamped event.



## Configuration

### Configure your MISP instance.

- If you don't have it, create an organisation for Cluster25.
You can do this from the main page, ```Administration -> Add Organisations```.
    
### Configure the tool (settings.py file).

- Set your client ID and client secret.

- Set the URL for the Cluster25 API.

- Configure the tool settings.

- Configure the settings referring to your MISP instance.


## Usage

### Optional clean.

Run a cleaning run of the script. This will remove all the Cluster25 events in your MISP instance. You can skip this 
if you don't have events tagged with the tags that this script uses or if you don't want to delete the events.

```bash
python3 /path/to/c25-misp-importer/c25-misp-importer/c25-misp-importer.py --clean-reports --clean-indicators --clean-actors
```

or if you want a complete clean-up:

```bash
python3 /path/to/c25-misp-importer/c25-misp-importer/c25-misp-importer.py --clean-all
```
### Periodic update.

Set up a cron job that will periodically run and pull the latest obejcts from the Cluster25 API
and push them as events in your MISP instance. To do this run the following commands.

```bash
crontab -e
```

This will let you edit your crontab file. Add the following line at the end of the file.

```bash
0 0 * * * python3 /path/to/c25-misp-importer/c25-misp-importer/c25-misp-importer.py --reports 2>&1 | /usr/bin/logger -t C25-MISP-IMPORTER
```

This will configure a cron job to run this script daily (recommended). You can find the logs of each run
in the ```/var/log/syslog``` file. 

Run the following command for more options:
   
```bash
python3 /path/to/c25-misp-importer/c25-misp-importer/c25-misp-importer.py --help
```

### Options

#### Cleanup options
- --clean-all → clean all events with  unique report, indicator or actor tags.
- --clean-reports → deletes all events with the unique report tag
- --clean-indicators → deletes all events with the unique indicator tag 
- --clean-actors → deletes all events with the unique actor tag 
- --max-event-age → delete events with timestamp older than max-event-age

#### Import options
- --reports → import report events
- --report-start-date → import reports from a specific start date in the format of: ```dd/mm/yyyy hh:mm:ss```. Default is 1 year before the execution.
- --indicators → import indicators in a single event for a specified time period.
- --indicators-start-date → import only indicators from a specific start date in the format of: ```dd/mm/yyyy hh:mm:ss```. Default is 1 year before the execution.
- --actors → imports all C25 existing actors generating an event per actor with detail information as objects and attributes.
#### General options
- --info → add more info to logs
- --help → show help



## Dependencies

To run this script, you need Python3 and the Python packages in the requirements.txt file. PyMisp 2.4.176 is the recommended version. However, using 2.4.178 to future-proof.



## Data Mapping Info

#### Reports → MISP Events 
- Reports are represented as a composition of MISP objects and attributes to display most of the information gathered from the Cluster25 CTI API.
- Tagged as "C25_EVENT"
- Supports galaxy cluster association for Threat Actors, Country, Attack Pattern and Malwares.


#### Indicators → Single MISP Event 
- An indicator event is represented as list of MISP attribute for each indicator gathered by the Cluster25 CTI API after a specified start date.
- Optional: each indicator can be enriched with the C25 expansion module for MISP. Check it out here: https://github.com/MISP/misp-modules
- Supports galaxy cluster association for Threat Actors, Country, Attack Pattern and Malwares.
- Tagged as "C25_INDICATORS"

#### Actors → MISP Events
- An actor event is represented as a MISP Event with respective objects and attribtues for each actor present in the Cluster25 CTI API.
- Supports galaxy cluster association for Threat Actors, Country, Attack Pattern and Malwares.
- Tagged as "C25_ACTOR"





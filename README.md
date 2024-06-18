# XDR_copy_and_paste_incidents

This repo contains some python scripts which help to copy an Incident from an XDR tenant in order to paste it into another tenant.

What motivated this project was Cyber Ranges exercices or Demo data for XDR. 

As a Threat Hunting plateform XDR is dedicated to Threat detection, mitigation and Investigations. 

When we learn to use the platform we need to work on attack scenarios.  That means that we must have some attacks to work on and by definition these attacks are complex and related to dangerous activities which are dangerous to reproduce into real networks.

But blue teams need real attack scenarios in order to learn how to be efficient when these attacks occur.

So the idea here is to not re do these real attacks, BUT put into XDR the result of these attacks. And as XDR is purely APIs based it is easy to achieve that.

In this repo we have one script that read an Incident you can select from a source XDR Tenant. And we have another script that create a new Incident into another tenant ( which can be the same tenant ).  

The first script save the selected Incident and every Indicators, Sightings, relationship, observables and targets it contains. All these Incident object are stored into one single JSON result ( incident_summary.json ). Then we can save the most interesting Incident into a external library for futur use like, investigation, post mortems, cyber range exercices.

The second script re create all the incident objects and their depedencies into the destination tenant.

## How to do

Step 1 : edit the **config.txt** file and update the variable value ( client_id, client_password, and URLs ), with the values needed to connect to the **SOURCE** XDR tenant.

Step 2 : Run the **1-select_and_get_incident-summary_from a_source_tenant.py** in order to select an Incident from the source XDR tenant

* When prompted select the Incident you want to copy
* This script calls the **incident-summary** API which collect a JSON result that contains every details of the selected Incident. This result is then stored into the **./incident_summary** subfolder as **incident_summary.json** file name.

Step 3 : edit the **config.txt** file again and update the variable value ( client_id, client_password, and URLs ), with the values needed to connect to the **DESTINATION** XDR tenant.

Step 4 : Then you must run the **0-ask_for_a_token.py** in order to ask for a new token for granting access to the new tenant. 

Step 5 : finally run the **2_paste_the_incident_into_a_destination_tenant.py** in order to paste the Incident from the **./incident_summary/incident_summary.json** file into the destination tenant.

## what do we paste into the destination tenant ?

We paste the following objects into the destination XDR tenant :

- Incident
- Every Incident Sightings
- Sightings Indicators

Actually the script reads the above objects from the **incident_summary.json** file and create these objects into the destination tenant. It is not just copy and pasting the existing JSON source definitions.

## Miscelaneous

The **SOURCE_FOR_EVERYTHING** designate a new source value to every create objects. It will help to identify them into the new tenant.

The new Incident is created with the current date and time, but not  Sightings and Indicators which are based on existing date and time values.  Search for the **SIGHTING DATE HERE** key word if you want to assign different date and time for sightings. This is the location within the code where to manage this.

If you don't want to paste every Incident sightings and select only some of them then locate the **YES_SELECT_THIS_SIGHTING** key word within the code. This is the location where to manage this.

## Utils

The **0-ask_for_a_token.py** asks for an XDR token and stores it as **cr_token.txt**. We don't need to run it for running the other scripts.

The **incident-summary_json_to_dtree_graph.py** that helps to visualize the **./incident_summary/incident_summary.json** file into a graph into the browser. It reads the **./incident_summary/incident_summary.json** and creates a clickable tree graph into the **./dtree** subfolder. Once the graph created open the **./dtree/index.html**

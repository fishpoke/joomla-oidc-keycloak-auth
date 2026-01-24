<?php

declare(strict_types=1);

defined('_JEXEC') or die;

use Joomla\CMS\Factory;
use Joomla\CMS\Form\Field\TextField;
use Joomla\CMS\Uri\Uri;

final class JFormFieldArticlesearch extends TextField
{
    protected $type = 'Articlesearch';

    protected function getInput()
    {
        $id = (string) ($this->id ?? '');
        $name = (string) ($this->name ?? '');
        $value = (int) ($this->value ?? 0);

        $db = Factory::getDbo();
        $title = '';
        if ($value > 0) {
            try {
                $query = $db->getQuery(true)
                    ->select($db->quoteName('title'))
                    ->from($db->quoteName('#__content'))
                    ->where($db->quoteName('id') . ' = ' . (int) $value);
                $db->setQuery($query);
                $title = (string) $db->loadResult();
            } catch (\Throwable $e) {
                $title = '';
            }
        }

        $base = rtrim((string) Uri::base(), '/');
        $ajaxUrl = $base . '/index.php?option=com_ajax&module=keycloak_login&method=searchArticles&format=json';

        $inputId = $id . '_search';
        $listId = $id . '_results';
        $hiddenId = $id;

        $titleEsc = htmlspecialchars($title, ENT_QUOTES, 'UTF-8');
        $ajaxUrlEsc = htmlspecialchars($ajaxUrl, ENT_QUOTES, 'UTF-8');

        $html = '';
        $html .= '<input type="hidden" id="' . htmlspecialchars($hiddenId, ENT_QUOTES, 'UTF-8') . '" name="' . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . '" value="' . (int) $value . '">';
        $html .= '<input type="text" class="form-control" id="' . htmlspecialchars($inputId, ENT_QUOTES, 'UTF-8') . '" value="' . $titleEsc . '" placeholder="Search..." autocomplete="off">';
        $html .= '<div class="list-group mt-2" id="' . htmlspecialchars($listId, ENT_QUOTES, 'UTF-8') . '" style="display:none;"></div>';

        $html .= '<script>';
        $html .= '(function(){';
        $html .= 'var input=document.getElementById(' . json_encode($inputId) . ');';
        $html .= 'var hidden=document.getElementById(' . json_encode($hiddenId) . ');';
        $html .= 'var list=document.getElementById(' . json_encode($listId) . ');';
        $html .= 'var ajaxUrl=' . json_encode($ajaxUrlEsc) . ';';
        $html .= 'var timer=null;';
        $html .= 'function clearList(){list.innerHTML="";list.style.display="none";}';
        $html .= 'function setItems(items){list.innerHTML="";';
        $html .= 'if(!items||!items.length){clearList();return;}';
        $html .= 'items.slice(0,5).forEach(function(it){';
        $html .= 'var a=document.createElement("a");a.href="#";a.className="list-group-item list-group-item-action";a.textContent=it.title;';
        $html .= 'a.addEventListener("click",function(ev){ev.preventDefault();hidden.value=it.id;input.value=it.title;clearList();});';
        $html .= 'list.appendChild(a);});';
        $html .= 'list.style.display="block";';
        $html .= '}';
        $html .= 'function search(){var term=(input.value||"").trim();';
        $html .= 'if(term.length<2){clearList();return;}';
        $html .= 'fetch(ajaxUrl+"&term="+encodeURIComponent(term),{credentials:"same-origin"})';
        $html .= '.then(function(r){return r.json();})';
        $html .= '.then(function(data){';
        $html .= 'var items=[];';
        $html .= 'if(data && data.items){items=data.items;}';
        $html .= 'else if(data && data.data && data.data.items){items=data.data.items;}';
        $html .= 'setItems(items);';
        $html .= '})';
        $html .= '.catch(function(){clearList();});';
        $html .= '}';
        $html .= 'input.addEventListener("input",function(){hidden.value="0";if(timer){clearTimeout(timer);}timer=setTimeout(search,250);});';
        $html .= 'document.addEventListener("click",function(ev){if(!list.contains(ev.target) && ev.target!==input){clearList();}});';
        $html .= '})();';
        $html .= '</script>';

        return $html;
    }
}
